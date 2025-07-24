# Firewall Automation

**Private script – not publicly available**

Contact: bondansvbianca@gmail.com

---

### Project Description

This project reads an Excel file containing:

- Source IPs  
- Destination IPs  
- Port/Protocol  
- Firewall IP  

It connects to the specified firewall and checks whether:

- Address objects exist  
- Services/ports are defined  
- Corresponding policies are present  

Depending on the results, the script can:

- Generate creation or deletion scripts  
- Apply the changes directly to the firewall  
- Save the command output for auditing

It generates a `.txt` file with the results for each IP and logs all changes made to the firewall.

---

## Libraries Used

```python
# -*- coding: utf-8 -*-
import pandas as pd
from netmiko import ConnectHandler
import traceback
import re 
import os
