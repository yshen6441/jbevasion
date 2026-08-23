#include <string.h>
#include <stdlib.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include "fishhook.h"

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;
static int _rebindings_successful = 0;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
  struct rebindings_entry *new_entry = malloc(sizeof(struct rebindings_entry));
  if (!new_entry) return -1;
  new_entry->rebindings = malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings) { free(new_entry); return -1; }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings_head,
                                            struct section_64 *section,
                                            intptr_t slide,
                                            struct nlist_64 *symtab,
                                            char *strtab,
                                            uint32_t *indirect_symtab) {
  if (!symtab || !strtab || !indirect_symtab) return;
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)section->addr + slide);
  for (uint32_t i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL) continue;
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    if (!strlen(symbol_name)) continue;
    struct rebindings_entry *cur = rebindings_head;
    while (cur) {
      for (size_t j = 0; j < cur->rebindings_nel; j++) {
        if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
          if (cur->rebindings[j].replaced != NULL && *(cur->rebindings[j].replaced) == NULL) {
            *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
          }
          indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
          goto next;
        }
      }
      cur = cur->next;
    }
    next:;
  }
}

static void _rebind_symbols_for_image(const struct mach_header *header,
                                       intptr_t slide) {
  struct rebindings_entry *rebindings_head = _rebindings_head;
  if (!rebindings_head) return;

  const struct mach_header_64 *header64 = (const struct mach_header_64 *)header;
  struct load_command *cmd = (struct load_command *)((uintptr_t)header + sizeof(struct mach_header_64));

  struct nlist_64 *symtab = NULL;
  char *strtab = NULL;
  uint32_t *indirect_symtab = NULL;

  for (uint32_t i = 0; i < header64->ncmds; i++) {
    switch (cmd->cmd) {
      case LC_SYMTAB: {
        struct symtab_command *symtab_cmd = (struct symtab_command *)cmd;
        symtab = (struct nlist_64 *)((uintptr_t)header + symtab_cmd->symoff);
        strtab = (char *)((uintptr_t)header + symtab_cmd->stroff);
        break;
      }
      case LC_DYSYMTAB: {
        struct dysymtab_command *dysymtab_cmd = (struct dysymtab_command *)cmd;
        indirect_symtab = (uint32_t *)((uintptr_t)header + dysymtab_cmd->indirectsymoff);
        break;
      }
      case LC_SEGMENT_64: {
        if (!symtab || !indirect_symtab) break;
        struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
        if (strcmp(seg->segname, SEG_DATA) != 0 && strcmp(seg->segname, SEG_DATA_CONST) != 0) break;
        for (uint32_t j = 0; j < seg->nsects; j++) {
          struct section_64 *sect = (struct section_64 *)((uintptr_t)seg + sizeof(struct segment_command_64) + sizeof(struct section_64) * j);
          if ((sect->flags & SECTION_TYPE) == S_LAZY_DYLIB_SYMBOL_POINTERS ||
              (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
            perform_rebinding_with_section(rebindings_head, sect, slide, symtab, strtab, indirect_symtab);
          }
        }
        break;
      }
    }
    cmd = (struct load_command *)((uintptr_t)cmd + cmd->cmdsize);
  }
}

int rebind_symbols_image(void *header,
                          intptr_t slide,
                          struct rebinding rebindings[],
                          size_t rebindings_nel) {
  if (rebindings && rebindings_nel > 0) {
    struct rebindings_entry *head = NULL;
    prepend_rebindings(&head, rebindings, rebindings_nel);
    struct rebindings_entry *rebindings_head = _rebindings_head;
    if (!rebindings_head) return -1;
    _rebind_symbols_for_image((const struct mach_header *)header, slide);
    free(head->rebindings);
    free(head);
  } else {
    _rebind_symbols_for_image((const struct mach_header *)header, slide);
  }
  return 0;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  if (prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel) < 0) return -1;
  if (!_rebindings_successful) {
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
    _rebindings_successful = 1;
  } else {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
      _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return 0;
}