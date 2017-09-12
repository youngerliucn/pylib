## Build

release tgz package:

~~~
python setup.py sdist
~~~



release rpm package:

```
python setup.py bdist_rpm
```



##Install & Unstall

~~~
rpm -ivh yynas-0.0.1.noarch.rpm
rpm -e yynas
~~~



## Usage

~~~
from yynas.ippy import IpLib
IpLib.ESUCCESS
~~~



