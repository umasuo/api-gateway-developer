package com.umasuo.gateway.developer.config;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Ignore rule.
 */
@Data
public class IgnoreRule {

  private String host;

  private String path;

  private String method;
}
