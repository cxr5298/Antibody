#  Antibody

This is a classification Support Vector Machine approach to statistical analysis and evaluation of DNS traffic and its probability of being a product of a DNS tunnel. Contained within the Antibody is:
- `collection and preprocessing` : a folder containing scripts needed to capture DNS packets for use as training data for the Antibody Support Vector Machine. Additionally it has two test capture files one for inbound and another for outbound DNS traffic.
- `antibody.py` : The actual Support Vector implementation along with realtime plotting and analytics
- `preProcessing.py` and `preProcessing.pyc` : The functions used by the `antibody` to train and evaluate DNS traffic.

# Setup
This project requires `Python 2.7.12` or later to run

## Dependencies:
`pip install -r reqs.txt`

## Usage:
`sudo ./antibody.py -<i|o> -t <path/to/trainingFile.cap> -s <interval in minutes>`
 - The file needs to be run as super so scapy can sniff packets on port 53

# Authors:
- Chris Remillard (CrMallard)
- Alvin Lin (omgimanerd)
- Stefan Aleksic (ColdSauce)
