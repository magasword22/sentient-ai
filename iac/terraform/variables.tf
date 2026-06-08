variable "aws_region" {
  type        = string
  description = "The target AWS region to deploy the security VM."
  default     = "us-east-1"
}

variable "instance_type" {
  type        = string
  description = "The EC2 instance type. t3.xlarge (16GB RAM) or g4dn.xlarge (GPU with 16GB VRAM) recommended."
  default     = "t3.xlarge"
}

variable "ssh_key_name" {
  type        = string
  description = "The name of the AWS EC2 SSH key pair to associate with the instance."
}

variable "admin_cidr" {
  type        = string
  description = "IP CIDR permitted to connect to SSH and Streamlit dashboard (strictly limit for security!)."
  default     = "0.0.0.0/0"
}
