#!/usr/bin/env bash

set -o errexit
set -o pipefail
# set -o xtrace

TERRAFORM=$(pwd)/bin/terraform

main() {
    if [ ! -e $TERRAFORM ]; then
        echo "Getting the correct version of terraform ..."
        # Detect the platform
        rm -rf bin || true
        mkdir bin
        cd bin
        OS="`uname`"
        case $OS in
            'Linux')
                wget https://releases.hashicorp.com/terraform/0.9.11/terraform_0.9.11_linux_amd64.zip
                unzip -o terraform_0.9.11_linux_amd64.zip
                rm terraform_0.9.11_linux_amd64.zip
                cd ..
                ;;
            'FreeBSD')
                wget https://releases.hashicorp.com/terraform/0.9.11/terraform_0.9.11_freebsd_amd64.zip
                unzip terraform_0.9.11_freebsd_amd64.zip
                rm terraform_0.9.11_freebsd_amd64.zip
                cd ..
                ;;
            'Darwin')
                wget https://releases.hashicorp.com/terraform/0.9.11/terraform_0.9.11_darwin_amd64.zip
                unzip terraform_0.9.11_darwin_amd64.zip
                rm terraform_0.9.11_darwin_amd64.zip
                cd ..
                ;;
            'SunOS')
                wget https://releases.hashicorp.com/terraform/0.9.11/terraform_0.9.11_solaris_amd64.zip
                unzip terraform_0.9.11_solaris_amd64.zip
                rm terraform_0.9.11_solaris_amd64.zip
                cd ..
                ;;
            *)
                cd ..
                echo "Couldn't determine os type."
                exit 1
                ;;
        esac
        echo ""
        echo "Terraform for $OS added to $(pwd)/bin/ directory."
        echo ""
    fi
    
    if [[ ! -z "$1" && "$1" == "-c" ]]; then
        destroyEnv
        exit 0
    fi

    if [ -e azure/main.tf ]; then
        echo "error: environment from a previous run has been found"
        echo "    clean the configuration (./setup-env-azure.sh -c)"
        exit
    fi

    # SET default variables from variables.template
    setVarDefaults
    # GET updated configuration from user input
    getConfigFromUser
    # VERIFY with user that parameters are correct
    verifyConfig
    # EXPORT environment variables for anything not stored in variables.tf
    setVariables
    
    echo "################################################################################"
    echo "### Starting terraform tasks..."
    echo "################################################################################"
    export TF_VAR_client_id=$client_id
    export TF_VAR_client_secret=$client_secret
    export TF_VAR_clusterPassword=$clusterPassword
    sleep 2
    runTerraformTasks

    # UNSET environment variables for anything exported
    unsetVars
}

getArgument() {
    # $1 message
    # $2 default
    while true; do
        local theargument
        if [[ $# -eq 1 ]]; then
            read -p "$1 " theargument
        elif [[ $# -eq 2 ]] && [[ $2 == "" ]]; then
            read -p "$1 " theargument
        elif [[ $# -eq 2 ]]; then
            read -p "$1 ($2) " theargument
        else
            break
        fi
        
        # input provided
        [[ ${#theargument} -gt 0 ]] && echo $theargument && break
        
        # input and default are both blank
        [[ $# -eq 2 ]] && [[ $2 == "" ]] && [[ $theargument == "" ]] && echo "" && break
        
        # input not provided, default provided
        [[ $# -eq 2 ]] && [[ $theargument == "" ]] && [[ ${#2} -gt 0 ]] && echo $2 && break
    done
}
runTerraformTasks() {
    for (( i = 1; i <= $numberOfNodes; i++ ))
    do
        echo "    Kubernetes node $i: $(echo ${hostname}${i} | sed 's/"//g')"
        updateTerraformConfig host $(echo ${hostname}${i} | sed 's/"//g')
    done
    if $SEPARATE_PLANE; then
        updateTerraformConfig k8setcd $(echo ${hostname}etcd1 | sed 's/"//g')
        updateTerraformConfig k8setcd $(echo ${hostname}etcd2 | sed 's/"//g')
        updateTerraformConfig k8setcd $(echo ${hostname}etcd3 | sed 's/"//g')
        updateTerraformConfig k8sha $(echo ${hostname}srvs1 | sed 's/"//g')
        updateTerraformConfig k8sha $(echo ${hostname}srvs2 | sed 's/"//g')
        updateTerraformConfig k8sha $(echo ${hostname}srvs3 | sed 's/"//g')
    fi
    cd azure
    echo "Starting terraform tasks"
    # terraform init --plugin-dir=$GOBIN
    $TERRAFORM get
    $TERRAFORM apply
    echo "    terraform tasks completed"
    cd ..
}
updateTerraformConfig() {
    cd azure
    
    echo "resource \"azurerm_public_ip\" \"${2}pip\" {
      name                         = \"${2}pip\"
      location                     = \"\${var.location}\"
      resource_group_name          = \"\${azurerm_resource_group.rg.name}\"
      public_ip_address_allocation = \"static\"
    }" >> main.tf

    echo "resource \"azurerm_network_interface\" \"${2}nic\" {
      name                = \"${2}nic\"
      location            = \"\${var.location}\"
      resource_group_name = \"\${azurerm_resource_group.rg.name}\"
      ip_configuration {
        name                          = \"\${var.rg_prefix}${2}ipconfig\"
        subnet_id                     = \"\${azurerm_subnet.subnet.id}\"
        private_ip_address_allocation = \"dynamic\"
        public_ip_address_id          = \"\${azurerm_public_ip.${2}pip.id}\"
      }
    }" >> main.tf

    echo "resource \"azurerm_virtual_machine\" \"$2\" {
      name                  = \"$2\"
      location              = \"\${azurerm_resource_group.rg.location}\"
      resource_group_name   = \"\${azurerm_resource_group.rg.name}\"
      network_interface_ids = [\"\${azurerm_network_interface.${2}nic.id}\"]
      vm_size               = \"\${var.vm_size}\"
      storage_image_reference {
        publisher = \"Canonical\"
        offer     = \"UbuntuServer\"
        sku       = \"16.04-LTS\"
        version   = \"latest\"
      }
      storage_os_disk {
        name          = \"${2}osdisk\"
        caching       = \"ReadWrite\"
        create_option = \"FromImage\"
        managed_disk_type = \"\${var.storage_account_type}\"
      }
      os_profile {
        computer_name  = \"${2}\"
        admin_username = \"\${var.admin_username}\"
        admin_password = \"\${var.admin_password}\"
      }
      os_profile_linux_config {
        disable_password_authentication = true
        ssh_keys = [{
          path     = \"/home/\${var.admin_username}/.ssh/authorized_keys\"
          key_data = \"\${file(\"\${var.ssh_key}.pub\")}\"
        }]
      }
      connection {
        type        = \"ssh\"
        user        = \"\${var.admin_username}\"
        password    = \"\${var.admin_password}\"
        host        = \"\${azurerm_public_ip.${2}pip.ip_address}\"
        private_key = \"\${file(\"\${var.ssh_key}\")}\"
      }
      provisioner \"remote-exec\" {
        inline = [
          \"curl https://releases.rancher.com/install-docker/1.12.sh | sudo sh\",
          \"sleep 5\"," >> main.tf
    if [ $1 == "k8sha" ]; then
        echo "      \"${k8sha_agent_container}\"," >> main.tf
    elif [ $1 == "k8setcd" ]; then
        echo "      \"sudo ${k8setcd_agent_container}\"," >> main.tf
    else
        echo "      \"sudo ${k8shost_agent_container}\"," >> main.tf
    fi
    echo "      \"sleep 1\",
        ]
      }
    }" >> main.tf

    echo "output \"${2}\" {
      value = \"\${azurerm_public_ip.${2}pip.ip_address}\"
    }" >> outputs.tf
    cd ..
}
setVariables() {
    cd azure
    cp variables.template variables.tf
    cp main.template main.tf
    
    # don't store these variables, exported as env variables
    #  client_id
    #  client_secret
    #  clusterPassword
    export TF_VAR_client_id
    export TF_VAR_client_secret
    export TF_VAR_clusterPassword

    echo "variable \"clusterLocation\" {
      default = \"$clusterLocation\"
    }" >> variables.tf
    echo "variable \"clusterAccessKey\" {
      default = \"$clusterAccessKey\"
    }" >> variables.tf
    echo "variable \"environmentName\" {
      default = \"$environmentName\"
    }" >> variables.tf
    echo "variable \"environmentDescription\" {
      default = \"$environmentDescription\"
    }" >> variables.tf
    echo "variable \"hostname\" {
      default = \"$hostname\"
    }" >> variables.tf
    echo "variable \"vm_size\" {
      default = \"$vm_size\"
    }" >> variables.tf
    echo "variable \"numberOfNodes\" {
      default = \"$numberOfNodes\"
    }" >> variables.tf
    echo "variable \"subscription_id\" {
      default = \"$subscription_id\"
    }" >> variables.tf
    echo "variable \"tenant_id\" {
      default = \"$tenant_id\"
    }" >> variables.tf
    echo "variable \"resource_group\" {
      default = \"$resource_group\"
    }" >> variables.tf
    echo "variable \"rg_prefix\" {
      default = \"$rg_prefix\"
    }" >> variables.tf
    echo "variable \"location\" {
      default = \"$location\"
    }" >> variables.tf
    echo "variable \"storage_account_name\" {
      default = \"$storage_account_name\"
    }" >> variables.tf
    echo "variable \"ssh_key\" {
      default = \"$ssh_key\"
    }" >> variables.tf
    
    # get k8s template and set it
    template_id=$(mycurl "http://$clusterLocation:8080/v2-beta/projectTemplates?name=kubernetes" | jq ".data[0].id" | sed 's/"//g')
    if $SEPARATE_PLANE; then
        mycurl -X PUT -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{"accountId":null, "data":{"fields":{"stacks":[{"name":"healthcheck", "templateId":"library:infra*healthcheck"}, {"name":"kubernetes", "templateId":"library:infra*k8s", "answers":{"CONSTRAINT_TYPE":"required", "CLOUD_PROVIDER":"rancher", "REGISTRY":"", "DISABLE_ADDONS":"false", "POD_INFRA_CONTAINER_IMAGE":"gcr.io/google_containers/pause-amd64:3.0", "INFLUXDB_HOST_PATH":"", "EMBEDDED_BACKUPS":true, "BACKUP_PERIOD":"15m0s", "BACKUP_RETENTION":"24h", "ETCD_HEARTBEAT_INTERVAL":"500", "ETCD_ELECTION_TIMEOUT":"5000"}}, {"name":"network-services", "templateId":"library:infra*network-services"}, {"name":"ipsec", "templateId":"library:infra*ipsec"}]}}, "description":"Default Kubernetes template", "externalId":"catalog://library:project*kubernetes:0", "id":0, "isPublic":true, "kind":"projectTemplate", "name":"Kubernetes", "removeTime":null, "removed":null, "state":"active", "transitioning":"no", "transitioningMessage":null, "transitioningProgress":0, "stacks":[{"type":"catalogTemplate", "name":"healthcheck", "templateId":"library:infra*healthcheck"}, {"type":"catalogTemplate", "answers":{"CONSTRAINT_TYPE":"required", "CLOUD_PROVIDER":"rancher", "REGISTRY":"", "DISABLE_ADDONS":"false", "POD_INFRA_CONTAINER_IMAGE":"gcr.io/google_containers/pause-amd64:3.0", "INFLUXDB_HOST_PATH":"", "EMBEDDED_BACKUPS":true, "BACKUP_PERIOD":"15m0s", "BACKUP_RETENTION":"24h", "ETCD_HEARTBEAT_INTERVAL":"500", "ETCD_ELECTION_TIMEOUT":"5000"}, "name":"kubernetes", "templateId":"library:infra*k8s"}, {"type":"catalogTemplate", "name":"network-services", "templateId":"library:infra*network-services"}, {"type":"catalogTemplate", "name":"ipsec", "templateId":"library:infra*ipsec"}]}' "http://$clusterLocation:8080/v2-beta/projecttemplates/$template_id" > /dev/null 2>&1
    else
        mycurl -X PUT -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{"accountId":null, "data":{"fields":{"stacks":[{"name":"healthcheck", "templateId":"library:infra*healthcheck"}, {"answers":{"CONSTRAINT_TYPE":"none", "CLOUD_PROVIDER":"rancher", "RBAC":false, "REGISTRY":"", "DNS_REPLICAS":"1", "ENABLE_RANCHER_INGRESS_CONTROLLER":true, "ENABLE_ADDONS":true, "POD_INFRA_CONTAINER_IMAGE":"gcr.io/google_containers/pause-amd64:3.0", "AUDIT_LOGS":false, "INFLUXDB_HOST_PATH":"", "ADDITIONAL_KUBELET_FLAGS":"", "EMBEDDED_BACKUPS":true, "BACKUP_PERIOD":"15m0s", "BACKUP_RETENTION":"24h", "ETCD_HEARTBEAT_INTERVAL":"500", "ETCD_ELECTION_TIMEOUT":"5000", "RANCHER_LB_SEPARATOR":"rancherlb"}, "name":"kubernetes", "templateId":"library:infra*k8s"}, {"name":"network-services", "templateId":"library:infra*network-services"}, {"name":"ipsec", "templateId":"library:infra*ipsec"}]}}, "description":"Default Kubernetes template", "externalId":"catalog://library:project*kubernetes:0", "id":0, "isPublic":true, "kind":"projectTemplate", "name":"Kubernetes", "removeTime":null, "removed":null, "state":"active", "transitioning":"no", "transitioningMessage":null, "transitioningProgress":0, "stacks":[{"type":"catalogTemplate", "name":"healthcheck", "templateId":"library:infra*healthcheck"}, {"type":"catalogTemplate", "answers":{"CONSTRAINT_TYPE":"none", "CLOUD_PROVIDER":"rancher", "RBAC":false, "REGISTRY":"", "DNS_REPLICAS":"1", "ENABLE_RANCHER_INGRESS_CONTROLLER":true, "ENABLE_ADDONS":true, "POD_INFRA_CONTAINER_IMAGE":"gcr.io/google_containers/pause-amd64:3.0", "AUDIT_LOGS":false, "INFLUXDB_HOST_PATH":"", "ADDITIONAL_KUBELET_FLAGS":"", "EMBEDDED_BACKUPS":true, "BACKUP_PERIOD":"15m0s", "BACKUP_RETENTION":"24h", "ETCD_HEARTBEAT_INTERVAL":"500", "ETCD_ELECTION_TIMEOUT":"5000", "RANCHER_LB_SEPARATOR":"rancherlb"}, "name":"kubernetes", "templateId":"library:infra*k8s"}, {"type":"catalogTemplate", "name":"network-services", "templateId":"library:infra*network-services"}, {"type":"catalogTemplate", "name":"ipsec", "templateId":"library:infra*ipsec"}]}' "http://${clusterLocation}:8080/v2-beta/projecttemplates/$template_id" > /dev/null 2>&1
    fi
    # create env and get id
    env_data=$(echo '{ "description":"kubernetes_description", "name":"kubernetes_name", "projectTemplateId":"kubernetes_template_id", "allowSystemRole":false, "members":[], "virtualMachine":false, "servicesPortRange":null, "projectLinks":[]}' | sed "s/kubernetes_description/${environmentDescription}/g" | sed "s/kubernetes_name/${environmentName}/g" | sed "s/kubernetes_template_id/${template_id}/g")
    environment_id=$(mycurl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d "$env_data" "http://${clusterLocation}:8080/v2-beta/projects" | jq ".id" | sed 's/"//g')
    # get agent registration token
    mycurl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{"description":"k8sagents", "name":"k8s agents registration token"}' "http://${clusterLocation}:8080/v2-beta/projects/${environment_id}/registrationtokens" >> /dev/null 2>&1
    agentImage=$(mycurl "http://${clusterLocation}:8080/v2-beta/projects/${environment_id}/registrationtokens" | jq ".data[0].image" | sed 's/"//g')
    agentRegistrationUrl=$(mycurl "http://${clusterLocation}:8080/v2-beta/projects/${environment_id}/registrationtokens" | jq ".data[0].registrationUrl" | sed 's/"//g')
    
    export k8sha_agent_container="docker run -e CATTLE_HOST_LABELS='orchestration=true' --rm --privileged -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/rancher:/var/lib/rancher ${agentImage} ${agentRegistrationUrl}"
    export k8setcd_agent_container="docker run -e CATTLE_HOST_LABELS='etcd=true' --rm --privileged -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/rancher:/var/lib/rancher ${agentImage} ${agentRegistrationUrl}"
    export k8shost_agent_container="docker run -e CATTLE_HOST_LABELS='compute=true' --rm --privileged -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/rancher:/var/lib/rancher ${agentImage} ${agentRegistrationUrl}"
    
    cd ..
}
mycurl() {
    if [ ! -z ${clusterAccessKey+x} ]; then
        curl -s -u "$clusterAccessKey:$clusterSecretKey" "$@"
    else
        curl -s "$@"
    fi
}
setVarDefaults() {
    if [ -e azure/variables.tf ]; then
        echo "error: old environment configuration found"
        destroyEnv
    fi

    export clusterLocation=
    export clusterAccessKey=
    export clusterSecretKey=
    
    export environmentName="dev-azure"
    export environmentDescription="dev-azure"
    export hostname=
    export vm_size="Standard_A0"
    export numberOfNodes=1
    export SEPARATE_PLANE=false
    
    export subscription_id=
    export client_id=
    export client_secret=
    export tenant_id=
    export resource_group=
    export rg_prefix="k8srg"
    export location="West US"
    export storage_account_name=
    export ssh_key=${HOME}/.ssh/id_rsa
}
getConfigFromUser() {
    local tmp=0
    local gotValidInput=false
    local tmp_ValidatedInput
    
    echo "---------------"
    clusterLocation=$(getArgument "Where is the cluster manager running:")
    echo "---------------"
    clusterAccessKey=$(getArgument "Cluster manager API Access Key (leave blank if authentication not set):" "")
    echo "---------------"
    clusterSecretKey=$(getArgument "Cluster Manager API Secret Key (leave blank if authentication not set):" "")
    echo "---------------"
    subscription_id=$(getArgument "Azure subscription id:")
    echo "---------------"
    tenant_id=$(getArgument "Tenant ID:")
    echo "---------------"
    client_id=$(getArgument "Client id:")
    echo "---------------"
    client_secret=$(getArgument "Client secret:")
    echo "---------------"
    environmentName=$(getArgument "Name your Kubernetes environment:" "$(echo $environmentName | sed 's/"//g')")
    echo "---------------"
    environmentDescription=$(getArgument "Describe this Kubernetes environment:" "$(echo $environmentDescription | sed 's/"//g')")
    echo "---------------"
    gotValidInput=false
    while ! $gotValidInput; do
        read -p "Run Kubernetes Management Services on dedicated nodes (+3 VMs for etcd, +3 VMs for K8s services - apiserver/scheduler/controllermanager...) (yes | no)? " yn
        case $yn in
            yes )
                SEPARATE_PLANE=true
                gotValidInput=true
                ;;
            no )
                SEPARATE_PLANE=false
                gotValidInput=true
                ;;
            * ) echo "Please answer yes or no.";;
        esac
    done
    echo "---------------"
    hostname=$(getArgument "Hostname prefix for all vms:")
    echo "---------------"
    vm_size=$(getArgument "VM package to use:" "$(echo $vm_size | sed 's/"//g')")
    echo "---------------"
    resource_group=$(getArgument "Resource group name:")
    echo "---------------"
    gotValidInput=false
    while ! $gotValidInput; do
        tmp_ValidatedInput=$(getArgument "Resource group prefix to append before resources:" "$(echo $rg_prefix | sed 's/"//g')")
        if [[ $tmp_ValidatedInput == [a-z][0-9a-z]* ]]; then
            gotValidInput=true
        else
            echo "error: Enter a valid value or leave blank to use the default."
            echo "    Must start with a letter and can only include lowercase letters and numbers"
        fi
    done
    rg_prefix=$tmp_ValidatedInput
    echo "---------------"
    gotValidInput=false
    while ! $gotValidInput; do
        tmp_ValidatedInput=$(getArgument "Location for all the resources:" "$(echo $location | sed 's/"//g')")
        if [[ $tmp_ValidatedInput =~ ^[A-Z][a-zA-Z\ 0-9]*$ ]]; then
            gotValidInput=true
        else
            echo "error: Enter a valid value or leave blank to use the default."
            echo "    Must start with a letter and can only include lowercase letters and numbers"
        fi
    done
    location=$tmp_ValidatedInput
    echo "---------------"
    storage_account_name=$(getArgument "Storage account name:")
    echo "---------------"
    gotValidInput=false
    while ! $gotValidInput; do
        tmp_ValidatedInput=$(getArgument "How many nodes should this Kubernetes cluster have:" "$(echo $numberOfNodes | sed 's/"//g')")
        if [[ $tmp_ValidatedInput =~ ^[1-9]$ ]]; then
            gotValidInput=true
        else
            echo "error: Enter a valid value (1-9) or leave blank to use the default."
        fi
    done
    numberOfNodes=$tmp_ValidatedInput
    echo "---------------"
    ssh_key=$(getArgument "SSH private key to use for all VMs (make sure public key is in the same directory):" "$(echo $ssh_key | sed 's/"//g')")
}
verifyConfig() {
    echo "################################################################################"
    echo "Verify that the following configuration is correct:"
    echo ""
    echo "Cluster Manager is at: $clusterLocation"
    echo "Name of kubernetes environment: $environmentName"
    echo "Kubernetes environment description: $environmentDescription"
    echo ""
    echo "Azure subscription id: $subscription_id"
    echo "Azure tenant id: $tenant_id"
    echo "Resource group $resource_group and storage account $storage_account_name will be created."
    echo ""
    echo "All hostnames will start with $hostname followed by a number."
    echo "Kubernetes environment will have $numberOfNodes nodes"
    echo "This package will be used for all the hosts: $vm_size"
    echo "The entire environment and associated resources will be in $location"
    echo ""
    echo "Make sure the above information is correct before answering:"

    while true; do
    read -p "Is the above config correct (yes | no)? " yn
    case $yn in
        yes )
            break
            ;;
        no )
            exit 0
            ;;
        * ) echo "Please answer yes or no.";;
    esac
    done
}
destroyEnv() {
    echo "Clearing settings...."
    while true; do
        echo "delete old azure config?"
        if [ -e azure/main.tf ]; then
            echo "WARNING: You are about to destroy your azure k8s environment."
        
            read -p "Do you wish to destroy the VMs and reset configuration (yes | no)? " yn
        else
            read -p "Do you wish to reset configuration (yes | no)? " yn
        fi
        case $yn in
            yes )
                if [ -e azure/main.tf ]; then
                    cd azure
                    echo "    destroying images..."
                    $TERRAFORM destroy -force 2> /dev/null || true
                    cd ..
                fi
                rm azure/main.tf azure/variables.tf azure/outputs.tf >> /dev/null 2>&1 || true
                rm azure/terraform.tfstate* >> /dev/null 2>&1 || true
                unsetVars
                echo "    All clear!"
                return;;
            no ) exit;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}
unsetVars() {
    unset clusterLocation
    unset clusterAccessKey
    unset clusterSecretKey
    
    unset environmentName
    unset environmentDescription
    unset hostname
    unset vm_size
    unset numberOfNodes
    unset SEPARATE_PLANE
    
    unset subscription_id
    unset client_id
    unset client_secret
    unset tenant_id
    unset resource_group
    unset rg_prefix
    unset location
    unset storage_account_name
    
    unset TF_VAR_client_id
    unset TF_VAR_client_secret
    unset TF_VAR_clusterPassword
    
    unset k8sha_agent_container
    unset k8setcd_agent_container
    unset k8shost_agent_container
}

main "$@"
