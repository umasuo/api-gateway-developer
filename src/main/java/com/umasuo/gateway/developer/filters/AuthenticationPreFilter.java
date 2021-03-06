package com.umasuo.gateway.developer.filters;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.umasuo.gateway.developer.config.AuthFilterConfig;
import com.umasuo.gateway.developer.config.IgnoreRule;
import com.umasuo.gateway.developer.dto.AuthStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import static com.netflix.zuul.context.RequestContext.getCurrentContext;

/**
 * 权限验证第一步，这里只验证用户是否已经登陆，并获取其具体权限信息，将开发者ID，权限通过header传入具体service.
 */
@Component
public class AuthenticationPreFilter extends ZuulFilter {


  /**
   * Logger.
   */
  private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationPreFilter.class);

  /**
   * RestTemplate.
   */
  private transient RestTemplate restTemplate = new RestTemplate();

  /**
   * Authentication service uri.
   */
  @Value("${developer.service.uri:http://developer/}")
  private transient String authUri;

  /**
   * Auth filter config.
   */
  @Autowired
  private transient AuthFilterConfig config;

  /**
   * Filter type.
   *
   * @return string
   */
  @Override
  public String filterType() {
    // use "pre", so we can check the auth before router to back end services.
    return "pre";
  }

  /**
   * Filter order.
   *
   * @return int
   */
  @Override
  public int filterOrder() {
    return 6;
  }

  /**
   * Check if we need to run this filter for this request.
   *
   * @return boolean
   */
  @Override
  public boolean shouldFilter() {
    RequestContext ctx = getCurrentContext();
    String host = ctx.getRouteHost().getHost();
    HttpServletRequest request = ctx.getRequest();
    String method = request.getMethod();
    String path = request.getRequestURI();
    LOGGER.debug("Check for host: {}, path: {}, method: {}.", host, path, method);
    boolean shouldFilter = true;
    if (isPathMatch(path, method) || HttpMethod.OPTIONS.matches(method)) {
      LOGGER.debug("Ignore host: {}, Path: {}, action: {}.", host, path, method);
      shouldFilter = false;
    }
    return shouldFilter;
  }

  /**
   * Add path match for api control.
   *
   * @param path String path
   * @return boolean
   */
  private boolean isPathMatch(String path, String method) {
    List<IgnoreRule> rules = config.getRules();
    IgnoreRule existPath = rules.stream().filter(
        rule -> Pattern.matches(rule.getPath(), path) &&
            rule.getMethod().equals(method)

        //rule.getHost().equals(host)
    ).findAny().orElse(null);

    return existPath != null;
  }

  /**
   * Run function.
   *
   * @return always return null
   */
  @Override
  public Object run() {
    RequestContext ctx = getCurrentContext();
    HttpServletRequest request = ctx.getRequest();
    String token = request.getHeader("authorization");
    String developerId = request.getHeader("developerId");
    AuthStatus authStatus = checkAuthentication(token, developerId);
    if (authStatus != null && authStatus.isLogin()) {
      // if true, then set the developerId to header
      ctx.addZuulRequestHeader("developerId", authStatus.getDeveloperId());
      //TODO 添加权限
      LOGGER.info("Exit. Check auth success.");
    } else {
      // stop routing and return auth failed.
      ctx.setSendZuulResponse(false);
      ctx.addZuulResponseHeader("Access-Control-Allow-Origin", request.getHeader("Origin"));
      ctx.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
      LOGGER.info("Exit. check auth failed.");
    }
    return null;
  }

  /**
   * Check the auth status
   *
   * @param tokenString String
   * @return the customer id
   */
  public AuthStatus checkAuthentication(String tokenString, String developerId) {
    LOGGER.debug("Enter. token: {}, developerId: {}.", tokenString, developerId);
    try {
      assert tokenString != null;
      String token = tokenString.substring(7);

      String uri = authUri + "/v1/developers/" + developerId + "/status?token=" + token;

      LOGGER.debug("AuthUri: {}", uri);

      // TODO change it to
      AuthStatus authStatus = restTemplate.getForObject(uri, AuthStatus.class);
      LOGGER.debug("Exit. authStatus: {}", authStatus);
      return authStatus;
    } catch (RestClientException ex) {
      LOGGER.debug("Get customerId from authentication service failed.", ex);
      return null;
    }
  }
}
