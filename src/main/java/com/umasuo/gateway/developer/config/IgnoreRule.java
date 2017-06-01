package com.umasuo.gateway.developer.config;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Auth filter config.
 */
@Data
public class IgnoreRule {

  private String host;

  private String path;

  private String method;

}
