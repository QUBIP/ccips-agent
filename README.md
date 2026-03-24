<!-- # © 2026 Telefónica Innovación Digital 
(mattinantartiko.elorzaforcada@telefonica.com)

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License. -->
# ccips-agent
Pilot 3 CCIPS agent component

 © Mattin Antartiko Elorza Forcada
## Agents
In this scenario we are deploying two Agent running in docker mode.

```bash!
docker build -t ccips_agent .
```

Here you only need to run as follows in each agent.
```bash!
docker run -it --network host --cap-add ALL --name ccips_agent --rm ccips_agent
```

### How to check the entries:
* SPD entries:
```
ip xfrm policy list
```
* SAD entries:
```
ip xfrm state list
```

### Removing SAD and SPD entries from kernel

* SPD entries:
```
ip xfrm policy flush
```
* SAD entries:
```
ip xfrm state flush
```

### Removing entries from sysrepo

If you are running the ccips without using the cointainer, it could be possible to have some entries stuck in sysrepo. To remove them, under the directory `examples` in the ccips-controller proyect, there is an script called `removeEntries.go` that tries to remove the sysrepo entries associated with the SAD and SPD entries from a set of servers. 

Note that you should first kill the ccips process before trying to remove the entries from sysrepo. 
