#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include "policy.h"

static shield_config_t g_config;
static int g_loaded = 0;

static char g_current_proc_name[64] = {0};
static char g_current_bundle_id[128] = {0};

const char *shield_get_current_proc_name(void) {
  if (g_current_proc_name[0] == 0) {
    char buf[1024] = {0};
    uint32_t size = sizeof(buf) - 1;
    if (sysctlbyname("kern.procname", buf, &size, NULL, 0) == 0) {
      strncpy(g_current_proc_name, buf, sizeof(g_current_proc_name) - 1);
    }
  }
  return g_current_proc_name;
}

const char *shield_get_current_bundle_id(void) {
  if (g_current_bundle_id[0] == 0) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
      const char *name = _dyld_get_image_name(i);
      if (!name) continue;
      if (strstr(name, "/var/containers/Bundle/Application/") ||
          strstr(name, "/var/mobile/Containers/Bundle/Application/")) {
        const char *slash = strrchr(name, '/');
        if (slash) {
          snprintf(g_current_bundle_id, sizeof(g_current_bundle_id), "%s", slash + 1);
          char *dot = strrchr(g_current_bundle_id, '.');
          if (dot) *dot = 0;
        }
        break;
      }
    }
  }
  return g_current_bundle_id;
}

static shield_policy_t *find_policy_for_current_proc(void) {
  const char *name = shield_get_current_proc_name();
  const char *bundle = shield_get_current_bundle_id();

  for (int i = 0; i < g_config.policy_count; i++) {
    shield_policy_t *p = &g_config.policies[i];
    if (p->proc_name[0] && strcmp(p->proc_name, name) == 0) return p;
    if (p->bundle_id[0] && bundle[0] && strcmp(p->bundle_id, bundle) == 0) return p;
  }

  for (int i = 0; i < g_config.policy_count; i++) {
    shield_policy_t *p = &g_config.policies[i];
    if (p->proc_name[0] == 0 && p->bundle_id[0] == 0) return p;
  }

  return NULL;
}

bool shield_policy_should_hide(const char *path) {
  if (!path || !g_loaded) return false;

  shield_policy_t *policy = find_policy_for_current_proc();
  if (!policy) return false;

  for (int i = 0; i < policy->rule_count; i++) {
    shield_rule_t *rule = &policy->rules[i];
    if (strncmp(path, rule->prefix, strlen(rule->prefix)) == 0) {
      return rule->action == SHIELD_ACTION_HIDE;
    }
  }

  return false;
}

int shield_policy_add_rule(const char *proc_name, const char *bundle_id, const char *prefix, shield_action_t action) {
  if (g_config.policy_count >= SHIELD_MAX_POLICIES) return -1;

  shield_policy_t *policy = NULL;

  if (proc_name == NULL && bundle_id == NULL) {
    /* default policy: group all default rules into the first empty-identity policy */
    for (int i = 0; i < g_config.policy_count; i++) {
      shield_policy_t *p = &g_config.policies[i];
      if (p->proc_name[0] == 0 && p->bundle_id[0] == 0) { policy = p; break; }
    }
  } else {
    for (int i = 0; i < g_config.policy_count; i++) {
      shield_policy_t *p = &g_config.policies[i];
      if ((proc_name && p->proc_name[0] && strcmp(p->proc_name, proc_name) == 0) ||
          (bundle_id && p->bundle_id[0] && strcmp(p->bundle_id, bundle_id) == 0)) {
        policy = p;
        break;
      }
    }
  }

  if (!policy) {
    policy = &g_config.policies[g_config.policy_count++];
    memset(policy, 0, sizeof(shield_policy_t));
    if (proc_name) strncpy(policy->proc_name, proc_name, sizeof(policy->proc_name) - 1);
    if (bundle_id) strncpy(policy->bundle_id, bundle_id, sizeof(policy->bundle_id) - 1);
  }

  if (policy->rule_count >= SHIELD_MAX_PREFIXES) return -1;
  shield_rule_t *rule = &policy->rules[policy->rule_count++];
  strncpy(rule->prefix, prefix, sizeof(rule->prefix) - 1);
  rule->action = action;
  return 0;
}

int shield_policy_load_default(void) {
  g_loaded = 0;
  memset(&g_config, 0, sizeof(g_config));

  shield_policy_add_rule(NULL, NULL, "/var/jb", SHIELD_ACTION_HIDE);
  shield_policy_add_rule(NULL, NULL, "/private/preboot", SHIELD_ACTION_HIDE);
  shield_policy_add_rule(NULL, NULL, "/etc/apt", SHIELD_ACTION_HIDE);
  shield_policy_add_rule(NULL, NULL, "/Applications/Cydia.app", SHIELD_ACTION_HIDE);
  shield_policy_add_rule(NULL, NULL, "/Applications/Sileo.app", SHIELD_ACTION_HIDE);
  shield_policy_add_rule(NULL, NULL, "/Applications/Zebra.app", SHIELD_ACTION_HIDE);
  shield_policy_add_rule(NULL, NULL, "/private/var/lib/cydia", SHIELD_ACTION_HIDE);
  shield_policy_add_rule(NULL, NULL, "/private/var/tmp/cydia.log", SHIELD_ACTION_HIDE);

  g_loaded = 1;
  return 0;
}

int shield_policy_load_file(const char *path) {
  return shield_policy_load_default();
}