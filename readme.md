#### PDDNS
Poorly designed DNS whatever (I am not even sure what this is. A resolver? A client?)

#### Build
```shell
: git clone https://github.com/sskcvqikf/pddns.git
: cd pddns
: cmake -S. -Bbuild
: cd build && cmake --build .
```
If you want to install this, then do it directly by copying or linking this executable somewhere in your path.
#### Usage
Run `pddns -h` to show help message.

#### References
The goal of this program was primarily educational. So, here are some useful references that helped me out:
- https://github.com/EmilHernvall/dnsguide
- http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm