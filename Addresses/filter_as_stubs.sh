#!/bin/bash

var_i=0
while read numberAS;
    do 
        var_i=0
        while read NotStubs;
        do
            if [ ${numberAS} == ${NotStubs} ]; then
                echo ${numberAS};
                var_i=1
                break; 
            fi
        done < "Not_stubs.txt"
        if [ ${var_i} == 0 ]; then 
            echo ${numberAS} >> ItalianStubs1.txt;
        fi
    done < "itASNumbers.txt"