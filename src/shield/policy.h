#ifndef SHIELD_POLICY_H
#define SHIELD_POLICY_H

#include <stdbool.h>

#define SHIELD_MAX_PREFIXES 64
#define SHIELD_MAX_POLICIES 32
#define SHIELD_PATH_MAX 256

typedef enum {
  SHIELD_ACTION_HIDE,     
  SHIELD_ACTION_ALLOW,    
} shield_action_t;

typedef struct {
  char prefix[SHIELD_PATH_MAX]; 
  shield_action_t action;
} shield_rule_t;

typedef struct {
  char proc_name[64];          
  char bundle_id[128];         
  shield_rule_t rules[SHIELD_MAX_PREFIXES];
  int rule_count;
} shield_policy_t;

typedef struct {
  shield_policy_t policies[SHIELD_MAX_POLICIES];
  int policy_count;
} shield_config_t;

bool shield_policy_should_hide(const char *path);

int shield_policy_load_default(void);
int shield_policy_load_file(const char *path);
int shield_policy_add_rule(const char *proc_name, const char *bundle_id, const char *prefix, shield_action_t action);

const char *shield_get_current_proc_name(void);
const char *shield_get_current_bundle_id(void);

#endif