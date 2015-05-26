#!/bin/bash

######################
### DGF 20/05/2014 ###
######################

#########################################
### Dichiarazione costanti simboliche ###
#########################################

declare -r PATH_HOME="/opt/AGENT"
declare -r PATH_LOG=${PATH_HOME}"/Log"
declare -r PATH_WORK=${PATH_HOME}"/Work"
declare -r PATH_TIMESTAMPS="/opt/marcaturatemporale"
declare -r REMOTE_SERVER="XX.XX.XX.XX"
declare -r REMOTE_USER="remote_user"
declare -r REMOTE_DOWNLOAD_PATH="/LOG/DOWNLOAD"
#declare -r REMOTE_DOWNLOAD_PATH="/SERVER/DOWNLOAD/APP"
declare -r HOSTNAME=$(hostname)

###############################
### dichiearazione funzioni ###
###############################

function GetLog()
{
        DATA_LOG="$(date +%Y-%m-%d\ %H:%M:%S)"
        echo "${DATA_LOG} - $1" >> ${PATH_LOG}/opti_agent_$(date +%Y%m%d).log
}

function Yesterday()
{
        DAY_BEFORE=$(perl -MPOSIX -le 'print strftime("%Y*%m*%d",localtime(time - 86400))')
        #DAY_BEFORE=$(perl -MPOSIX -le 'print strftime("%Y*%m*%d",localtime(time - 172800))')
}

function GetFileTs()
{
        ls ${PATH_TIMESTAMPS}/output/*$1* > ${PATH_WORK}/tmp_list_file
        if [ $? -ne 0 ];then
                GetLog "[ERRORE] file non presenti esco"
                exit
        fi

        ### inizio costruzione file xml ###
        echo "<?xml version=\"1.0\"?>" > ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
        echo "<file_sent>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
        echo "  <server name=\""$(hostname)"\">"  >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
        echo "          <shipmentDate>"$(date +%Y-%m-%d)"</shipmentDate>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
        echo "  </server>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
        echo "  <file_list>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml

        while read i in
        do
                FILE_DATA=$(ls -l $i)
                echo "          <file name=\""$(echo ${FILE_DATA}|awk -F"/" '{print $5}')"\">" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
                echo "                  <md5sum>"$(openssl dgst -md5 $i|awk '{print $2}')"</md5sum>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
                echo "                  <size>"$(echo ${FILE_DATA}|awk '{print $5}')"</size>"  >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
                #echo "                 <file_date>"$(echo ${FILE_DATA}|awk -F"/" '{print $5}'|awk -F "." '{print $3}')"</file_date>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
                echo "                  <file_date>"$(echo $1|awk -F"*" '{print $1"-"$2"-"$3}')"</file_date>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
                echo "          </file>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml

        done < ${PATH_WORK}/tmp_list_file

        echo "  </file_list>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml
        echo "</file_sent>" >> ${PATH_WORK}/file_inviati_$(hostname)_$2.xml

}

function SendFileToOpti()
{
        ### trasferimento to optiserver del file timestamp ###
        su - conslog -c "scp ${PATH_TIMESTAMPS}/output/*$1*  ${REMOTE_USER}@${REMOTE_SERVER}:/${REMOTE_DOWNLOAD_PATH}/$2/"
        if [ $? -eq 0 ];then
                GetLog "[INFO] scp to optiserver andato a buon fine"
        else
                GetLog "[ERRORE] scp to optiserver andato male"
        fi

        ### trasferimento to optiserver del file xml ###
        su - conslog -c "scp ${PATH_WORK}/file_inviati_$(hostname)_$3.xml  ${REMOTE_USER}@${REMOTE_SERVER}:${REMOTE_DOWNLOAD_PATH}/$2/"
        if [ $? -eq 0 ];then
                GetLog "[INFO] scp to optiserver andato a buon fine"
        else
                GetLog "[ERRORE] scp to optiserver andato male"
        fi
}

function DeleteTmpFile()
{
        rm ${PATH_WORK}/tmp_list_file
        rm ${PATH_WORK}/file_inviati_$(hostname)_$1.xml
}

############
### MAIN ###
############
Yesterday

GetFileTs "${DAY_BEFORE}" "$(echo ${DAY_BEFORE}|awk -F\* '{print $1"-"$2"-"$3}')"
SendFileToOpti "${DAY_BEFORE}" "$(hostname)" "$(echo ${DAY_BEFORE}|awk -F\* '{print $1"-"$2"-"$3}')"
DeleteTmpFile "$(echo ${DAY_BEFORE}|awk -F\* '{print $1"-"$2"-"$3}')"


exit
#scp ${PATH_SNORT_LOG}/file.1.gz ${REMOTE_USER}@${REMOTE_SERVER}:${REMOTE_DOWNLOAD_PATH}/file.1_${DAY_BEFORE}.gz
if [ $? -eq 0 ];then
        GetLog "[INFO] il trasferimento del file e' andato a buon fine"
        GetLog "[INFO] il cksum del file e' : $(cksum ${PATH_SNORT_LOG}/file.1.gz)"
else
        GetLog "[ERRORE] il file non e' stato trasferito correttamente"
fi
