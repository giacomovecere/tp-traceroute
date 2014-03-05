#!/bin/bash

var_i=0
while read numberItAS;
    do 
        var_i=0
        while read Address ASnumber;
        do
            if [ ${numberItAS} == ${ASnumber} ]; then
                echo ${Address} " " ${numberItAS} >> Targets.txt
            fi
        done < "Prefix_AS.txt"
    done < "ItalianStubs.txt"