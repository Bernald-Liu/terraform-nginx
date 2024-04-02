# terraform-nginx

Executing Terraform Validate, the returned is success, the configuration is valid.

![Screenshot 2024-04-02 153848](https://github.com/Bernald-Liu/terraform-nginx/assets/38164160/9db02400-9203-434e-8a3b-da50a2a80466)



Executing Terraform Apply, the nginx infrastructure will be created as shown below:

# kubernetes_service.nginx will be created
  + resource "kubernetes_service" "nginx" {
      + id                     = (known after apply)
      + status                 = (known after apply)
      + wait_for_load_balancer = true

      + metadata {
          + generation       = (known after apply)
          + name             = "nginx-service"
          + namespace        = "default"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }

      + spec {
          + allocate_load_balancer_node_ports = true
          + cluster_ip                        = (known after apply)
          + cluster_ips                       = (known after apply)
          + external_traffic_policy           = (known after apply)
          + health_check_node_port            = (known after apply)
          + internal_traffic_policy           = (known after apply)
          + ip_families                       = (known after apply)
          + ip_family_policy                  = (known after apply)
          + publish_not_ready_addresses       = false
          + selector                          = {
              + "app" = "nginx"
            }
          + session_affinity                  = "None"
          + type                              = "LoadBalancer"

          + port {
              + node_port   = (known after apply)
              + port        = 80
              + protocol    = "TCP"
              + target_port = "80"
            }

          + session_affinity_config {
              + client_ip {
                  + timeout_seconds = (known after apply)
                }
            }
        }
    }

  # module.eks.data.http.wait_for_cluster[0] will be read during apply
  # (config refers to values not yet known)
 <= data "http" "wait_for_cluster" {
      + body             = (known after apply)
      + ca_certificate   = (known after apply)
      + id               = (known after apply)
      + response_headers = (known after apply)
      + timeout          = 300
      + url              = (known after apply)
    }

  # module.eks.aws_eks_cluster.this[0] will be created
  + resource "aws_eks_cluster" "this" {
      + arn                   = (known after apply)
      + certificate_authority = (known after apply)
      + cluster_id            = (known after apply)
      + created_at            = (known after apply)
      + endpoint              = (known after apply)
      + id                    = (known after apply)
      + identity              = (known after apply)
      + name                  = "eks-cluster"
      + platform_version      = (known after apply)
      + role_arn              = (known after apply)
      + status                = (known after apply)
      + tags_all              = (known after apply)
      + version               = "1.29"

      + kubernetes_network_config {
          + ip_family         = (known after apply)
          + service_ipv4_cidr = (known after apply)
          + service_ipv6_cidr = (known after apply)
        }

      + timeouts {
          + create = "30m"
          + delete = "15m"
          + update = "60m"
        }

      + vpc_config {
          + cluster_security_group_id = (known after apply)
          + endpoint_private_access   = false
          + endpoint_public_access    = true
          + public_access_cidrs       = [
              + "0.0.0.0/0",
            ]
          + security_group_ids        = (known after apply)
          + subnet_ids                = (known after apply)
          + vpc_id                    = (known after apply)
        }
    }

  # module.eks.aws_iam_policy.cluster_deny_log_group[0] will be created
  + resource "aws_iam_policy" "cluster_deny_log_group" {
      + arn         = (known after apply)
      + description = "Deny CreateLogGroup"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "eks-cluster-deny-log-group"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = "logs:CreateLogGroup"
                      + Effect   = "Deny"
                      + Resource = "*"
                      + Sid      = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # module.eks.aws_iam_policy.cluster_elb_sl_role_creation[0] will be created
  + resource "aws_iam_policy" "cluster_elb_sl_role_creation" {
      + arn         = (known after apply)
      + description = "Permissions for EKS to create AWSServiceRoleForElasticLoadBalancing service-linked role"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = "eks-cluster-elb-sl-role-creation"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "ec2:DescribeInternetGateways",
                          + "ec2:DescribeAddresses",
                          + "ec2:DescribeAccountAttributes",
                        ]
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # module.eks.aws_iam_role.cluster[0] will be created
  + resource "aws_iam_role" "cluster" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "eks.amazonaws.com"
                        }
                      + Sid       = "EKSClusterAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "eks-cluster"
      + path                  = "/"
      + role_last_used        = (known after apply)
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.eks.aws_iam_role.workers[0] will be created
  + resource "aws_iam_role" "workers" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = "EKSWorkerAssumeRole"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = true
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = "eks-cluster"
      + path                  = "/"
      + role_last_used        = (known after apply)
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.eks.aws_iam_role_policy_attachment.cluster_AmazonEKSClusterPolicy[0] will be created
  + resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSClusterPolicy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.cluster_AmazonEKSServicePolicy[0] will be created
  + resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSServicePolicy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.cluster_AmazonEKSVPCResourceControllerPolicy[0] will be created
  + resource "aws_iam_role_policy_attachment" "cluster_AmazonEKSVPCResourceControllerPolicy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.cluster_deny_log_group[0] will be created
  + resource "aws_iam_role_policy_attachment" "cluster_deny_log_group" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.cluster_elb_sl_role_creation[0] will be created
  + resource "aws_iam_role_policy_attachment" "cluster_elb_sl_role_creation" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.workers_AmazonEC2ContainerRegistryReadOnly[0] will be created
  + resource "aws_iam_role_policy_attachment" "workers_AmazonEC2ContainerRegistryReadOnly" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.workers_AmazonEKSWorkerNodePolicy[0] will be created
  + resource "aws_iam_role_policy_attachment" "workers_AmazonEKSWorkerNodePolicy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
      + role       = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.workers_AmazonEKS_CNI_Policy[0] will be created
  + resource "aws_iam_role_policy_attachment" "workers_AmazonEKS_CNI_Policy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
      + role       = (known after apply)
    }

  # module.eks.aws_security_group.cluster[0] will be created
  + resource "aws_security_group" "cluster" {
      + arn                    = (known after apply)
      + description            = "EKS cluster security group."
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "eks-cluster"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "eks-cluster-eks_cluster_sg"
        }
      + tags_all               = {
          + "Name" = "eks-cluster-eks_cluster_sg"
        }
      + vpc_id                 = (known after apply)
    }

  # module.eks.aws_security_group.workers[0] will be created
  + resource "aws_security_group" "workers" {
      + arn                    = (known after apply)
      + description            = "Security group for all nodes in the cluster."
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = "eks-cluster"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name"                              = "eks-cluster-eks_worker_sg"
          + "kubernetes.io/cluster/eks-cluster" = "owned"
        }
      + tags_all               = {
          + "Name"                              = "eks-cluster-eks_worker_sg"
          + "kubernetes.io/cluster/eks-cluster" = "owned"
        }
      + vpc_id                 = (known after apply)
    }

  # module.eks.aws_security_group_rule.cluster_egress_internet[0] will be created
  + resource "aws_security_group_rule" "cluster_egress_internet" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Allow cluster egress access to the Internet."
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.cluster_https_worker_ingress[0] will be created
  + resource "aws_security_group_rule" "cluster_https_worker_ingress" {
      + description              = "Allow pods to communicate with the EKS cluster API."
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.workers_egress_internet[0] will be created
  + resource "aws_security_group_rule" "workers_egress_internet" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Allow nodes all egress to the Internet."
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "egress"
    }

  # module.eks.aws_security_group_rule.workers_ingress_cluster[0] will be created
  + resource "aws_security_group_rule" "workers_ingress_cluster" {
      + description              = "Allow workers pods to receive communication from the cluster control plane."
      + from_port                = 1025
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 65535
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.workers_ingress_cluster_https[0] will be created
  + resource "aws_security_group_rule" "workers_ingress_cluster_https" {
      + description              = "Allow pods running extension API servers on port 443 to receive communication from cluster control plane."
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.workers_ingress_self[0] will be created
  + resource "aws_security_group_rule" "workers_ingress_self" {
      + description              = "Allow node to communicate with each other."
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + security_group_rule_id   = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 65535
      + type                     = "ingress"
    }

  # module.eks.kubernetes_config_map.aws_auth[0] will be created
  + resource "kubernetes_config_map" "aws_auth" {
      + data = (known after apply)
      + id   = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + labels           = {
              + "app.kubernetes.io/managed-by" = "Terraform"
              + "terraform.io/module"          = "terraform-aws-modules.eks.aws"
            }
          + name             = "aws-auth"
          + namespace        = "kube-system"
          + resource_version = (known after apply)
          + uid              = (known after apply)
        }
    }

  # module.eks.local_file.kubeconfig[0] will be created
  + resource "local_file" "kubeconfig" {
      + content              = (known after apply)
      + content_base64sha256 = (known after apply)
      + content_base64sha512 = (known after apply)
      + content_md5          = (known after apply)
      + content_sha1         = (known after apply)
      + content_sha256       = (known after apply)
      + content_sha512       = (known after apply)
      + directory_permission = "0755"
      + file_permission      = "0600"
      + filename             = "./kubeconfig_eks-cluster"
      + id                   = (known after apply)
    }

  # module.vpc.aws_eip.nat[0] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Name"                              = "eks-vpc-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all             = {
          + "Name"                              = "eks-vpc-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc                  = true
    }

  # module.vpc.aws_eip.nat[1] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Name"                              = "eks-vpc-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all             = {
          + "Name"                              = "eks-vpc-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc                  = true
    }

  # module.vpc.aws_eip.nat[2] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Name"                              = "eks-vpc-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all             = {
          + "Name"                              = "eks-vpc-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc                  = true
    }

  # module.vpc.aws_internet_gateway.this[0] will be created
  + resource "aws_internet_gateway" "this" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name"                              = "eks-vpc"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all = {
          + "Name"                              = "eks-vpc"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id   = (known after apply)
    }

  # module.vpc.aws_nat_gateway.this[0] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name"                              = "eks-vpc-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all             = {
          + "Name"                              = "eks-vpc-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
    }

  # module.vpc.aws_nat_gateway.this[1] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name"                              = "eks-vpc-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all             = {
          + "Name"                              = "eks-vpc-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
    }

  # module.vpc.aws_nat_gateway.this[2] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name"                              = "eks-vpc-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all             = {
          + "Name"                              = "eks-vpc-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
    }

  # module.vpc.aws_route.private_nat_gateway[0] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route.private_nat_gateway[1] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route.private_nat_gateway[2] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route.public_internet_gateway[0] will be created
  + resource "aws_route" "public_internet_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + gateway_id             = (known after apply)
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route_table.private[0] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all         = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table.private[1] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all         = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table.private[2] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all         = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table.public[0] will be created
  + resource "aws_route_table" "public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name"                              = "eks-vpc-public"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all         = {
          + "Name"                              = "eks-vpc-public"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[0] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[1] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[2] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[0] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[1] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[2] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_subnet.private[0] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "ap-southeast-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.1.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all                                       = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.private[1] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "ap-southeast-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.2.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all                                       = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.private[2] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "ap-southeast-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.3.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all                                       = {
          + "Name"                              = "eks-vpc-private-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[0] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "ap-southeast-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.101.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = true
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                              = "eks-vpc-public-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all                                       = {
          + "Name"                              = "eks-vpc-public-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[1] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "ap-southeast-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.102.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = true
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                              = "eks-vpc-public-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all                                       = {
          + "Name"                              = "eks-vpc-public-ap-southeast-1b"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[2] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "ap-southeast-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.103.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = true
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name"                              = "eks-vpc-public-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all                                       = {
          + "Name"                              = "eks-vpc-public-ap-southeast-1a"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_vpc.this[0] will be created
  + resource "aws_vpc" "this" {
      + arn                                  = (known after apply)
      + cidr_block                           = "10.0.0.0/16"
      + default_network_acl_id               = (known after apply)
      + default_route_table_id               = (known after apply)
      + default_security_group_id            = (known after apply)
      + dhcp_options_id                      = (known after apply)
      + enable_classiclink                   = (known after apply)
      + enable_classiclink_dns_support       = (known after apply)
      + enable_dns_hostnames                 = false
      + enable_dns_support                   = true
      + enable_network_address_usage_metrics = (known after apply)
      + id                                   = (known after apply)
      + instance_tenancy                     = "default"
      + ipv6_association_id                  = (known after apply)
      + ipv6_cidr_block                      = (known after apply)
      + ipv6_cidr_block_network_border_group = (known after apply)
      + main_route_table_id                  = (known after apply)
      + owner_id                             = (known after apply)
      + tags                                 = {
          + "Name"                              = "eks-vpc"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all                             = {
          + "Name"                              = "eks-vpc"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
    }

  # module.vpc.aws_vpn_gateway.this[0] will be created
  + resource "aws_vpn_gateway" "this" {
      + amazon_side_asn = "64512"
      + arn             = (known after apply)
      + id              = (known after apply)
      + tags            = {
          + "Name"                              = "eks-vpc"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + tags_all        = {
          + "Name"                              = "eks-vpc"
          + "kubernetes.io/cluster/eks-cluster" = "shared"
        }
      + vpc_id          = (known after apply)
    }

  # module.eks.module.node_groups.aws_eks_node_group.workers["ng1"] will be created
  + resource "aws_eks_node_group" "workers" {
      + ami_type               = (known after apply)
      + arn                    = (known after apply)
      + capacity_type          = (known after apply)
      + cluster_name           = "eks-cluster"
      + disk_size              = 100
      + id                     = (known after apply)
      + instance_types         = [
          + "m4.large",
        ]
      + node_group_name        = (known after apply)
      + node_group_name_prefix = "eks-cluster-ng1"
      + node_role_arn          = (known after apply)
      + release_version        = (known after apply)
      + resources              = (known after apply)
      + status                 = (known after apply)
      + subnet_ids             = (known after apply)
      + tags_all               = (known after apply)
      + version                = (known after apply)

      + scaling_config {
          + desired_size = 2
          + max_size     = 3
          + min_size     = 1
        }

      + timeouts {}

      + update_config {
          + max_unavailable            = (known after apply)
          + max_unavailable_percentage = (known after apply)
        }
    }

Plan: 55 to add, 0 to change, 0 to destroy.
