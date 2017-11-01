variable "hostname" {
  description = "hostname of the host to be added"
}

variable "networks" {
  type        = "list"
  description = "list of networks"
}

variable "root_authorized_keys" {
  default     = "~/.ssh/id_rsa"
  description = "public ssh key for root login"
}

variable "image" {
  default     = "80e13c87-76c8-4a25-bd1d-da3c846ccce8"
  description = "long image ID, default is ubuntu-certified-17.04"
}

variable "package" {
  default     = "k8s_32G"
  description = "triton package, default is k8s_32G"
}
