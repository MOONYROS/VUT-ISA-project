# ISA projekt (2023) - DHCP monitoring

The goal of this project was to create a program, that would get the statistics about the current state of network load using IP address prefix.

When the load is over 50%, the program will inform administrator on the `stdout` and also through `syslog`.

This problem is typically addressed in practice by parsing the assigned addresses from the DHCP server log, or alternatively, this information can sometimes be provided directly by the DHCP server. The goal of the project is to solve the situation where the DHCP server does not support this option, and to obtain the necessary statistics by monitoring DHCP traffic.

## Result

15/20