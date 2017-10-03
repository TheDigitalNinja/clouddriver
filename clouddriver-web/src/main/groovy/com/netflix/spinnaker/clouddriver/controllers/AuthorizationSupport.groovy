/*
 * Copyright 2016 Google, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.clouddriver.controllers

import com.netflix.frigga.Names
import com.netflix.spinnaker.clouddriver.model.LoadBalancerProvider
import com.netflix.spinnaker.fiat.shared.FiatPermissionEvaluator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import groovy.util.logging.Slf4j

/**
 * Support for controllers requiring authorization checks from Fiat.
 */
@Slf4j
@Component
class AuthorizationSupport {

  @Autowired
  FiatPermissionEvaluator permissionEvaluator

  /**
   * Performs READ authorization checks on returned Maps that are keyed by account name.
   * @param map Objected returned by a controller that has account names as the key
   * @return true always, to conform to Spring Security annotation expectation.
   */
  boolean filterForAccounts(Map<String, Object> map) {
    if (!map) {
      return true
    }

    Authentication auth = SecurityContextHolder.context.authentication;

    new HashMap(map).keySet().each { String account ->
      if (!permissionEvaluator.hasPermission(auth, account, 'ACCOUNT', 'READ')) {
        map.remove(account)
      }
    }
    return true
  }

  /**
   *   Used for filtering result lists by searching for "account"-like properties.
   */
  boolean filterForAccounts(List items) {
    if (!items) {
      return true
    }

    Authentication auth = SecurityContextHolder.context.authentication;

    new ArrayList<>(items).each { Object item ->
      Map propertySource = item.properties
      if (item instanceof Map) {
        propertySource = item
      }
      String account = propertySource.account ?: propertySource.accountName

      if (account && !permissionEvaluator.hasPermission(auth, account, 'ACCOUNT', 'READ')) {
        log.debug("RPERKINS: removing item for ${account.name}")
        items.remove(item)
      }
    }
    return true
  }

  boolean filterLoadBalancerProviderItems(List<LoadBalancerProvider.Item> lbItems) {
    if (!lbItems) {
      log.debug("RPERKINS: no lbItem 1")
      return true
    }

    new ArrayList<>(lbItems).each { LoadBalancerProvider.Item lbItem ->
      if(!filterLoadBalancerProviderItem(lbItem)) {
        log.debug("RPERKINS: Removing item ${lbItem.name}")
        lbItems.remove(lbItem)
      }
    }
    return true
  }

  boolean filterLoadBalancerProviderItem(LoadBalancerProvider.Item lbItem) {
    if (!lbItem) {
      log.debug("RPERKINS: no lbItem 2")
      return false
    }

    String application = Names.parseName(lbItem.name).app
    if (!application) {
      log.debug("RPERKINS: ${lbItem.name} has no application")
      return false
    }

    Authentication auth = SecurityContextHolder.context.authentication;

    if (!permissionEvaluator.hasPermission(auth, application, 'APPLICATION', 'READ')) {
      log.debug("RPERKINS: ${application} doesnt have permission")
      return false
    }

    new ArrayList<>(lbItem.byAccounts).each { LoadBalancerProvider.ByAccount account ->
      if (!permissionEvaluator.hasPermission(auth, account.name, 'ACCOUNT', 'READ')) {
        log.debug("RPERKINS: ${account.name} doesnt have permission")
        lbItem.byAccounts.remove(account)
      }
    }

    // It'd be weird if there was a load balancer with just name and an empty accounts field.
    if (!lbItem.byAccounts) {
      log.debug("RPERKINS: I guess its weird then for ${lbItem.name}")
      return false
    }
    return true
  }
}
