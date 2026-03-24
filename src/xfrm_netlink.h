/*# © 2026 Telefónica Innovación Digital 
#(mattinantartiko.elorzaforcada@telefonica.com)

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. */
#ifndef __XFRM_NETLINK_H
#define __XFRM_NETLINK_H

#include "sad_entry.h"

int xfrm_addsad_aead(sad_entry_node *sad_node);
int xfrm_delsad_aead(sad_entry_node *sad_node);

#endif