# Secret Splitter
![code quality](https://www.code-inspector.com/project/9583/status/svg)
![code quality](https://www.code-inspector.com/project/9583/score/svg)
![issues](https://img.shields.io/github/issues/elias-summermatter/sspliter)
![forks](https://img.shields.io/github/forks/elias-summermatter/sspliter)
![stars](https://img.shields.io/github/stars/elias-summermatter/sspliter)
![licence](https://img.shields.io/github/license/elias-summermatter/sspliter)
![Twitter](https://img.shields.io/twitter/url?url=https%3A%2F%2Fgithub.com%2Felias-summermatter%2Fsspliter)



Allows splitting secrets (or any other file) into n chucks for distributed storage. Restore of the secret is only possible with access to enough splits (can be defined).    
Following cryptographic functions are used:
- aes256: encrypt data
- argon2: Protect passphrase from bruteforce
- sha256: derive keys from main key

## Command-line arguments
    ssplit.py [mode] [options] [file1] [file2]...
    Mode:
      -e: Create new secret split
      -d: Decrypt secret from splits
    Options:
      -p [passphrase]: Optional Passphrase
      --argon-time [rounds]: Custom round count for argon [default 200]
      --argon-memory [kb]: Custom amount of memory needed for argon [default 100000]
      --distribution [number]: Create new secret split [ default 3]")
      --redundancy [number]: Create new secret split [ default 2]")

## Installation (With python virtual env)
1. `pip install pipenv`  
2. `pipenv install`  
3. `pipenv shell`  

## Warranty/Licence
### Secret Splitter  

Copyright (C) 2020  Elias Summermatter 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>





