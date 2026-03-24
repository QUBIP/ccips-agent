#ifndef __XFRM_NETLINK_H
#define __XFRM_NETLINK_H

#include "sad_entry.h"

int xfrm_addsad_aead(sad_entry_node *sad_node);
int xfrm_delsad_aead(sad_entry_node *sad_node);

#endif