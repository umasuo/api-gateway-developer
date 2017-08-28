package com.umasuo.gateway.developer.dto;

import lombok.Data;

/**
 * The auth status of this developer.
 */
@Data
public class AuthStatus {

  /**
   * Developer Id.
   */
  private String developerId;

  /**
   *  If this developer has login.
   */
  private boolean isLogin;

  // TODO: 17/6/21 后期添加scope等控制
}
