#!/bin/bash
cat AS_country.txt |
while read numberAS Nation; 
    do 
        if [ ${Nation} == "IT" ]; then
            echo ${numberAS} >> itASNumbers.txt;
        fi
    done