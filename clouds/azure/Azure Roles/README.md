# Synopsis

First part of this gist contains list of Azure RBAC and Azure AD roles sorted by their names.

Second part contains full definitions of each role along with their permissions assigned.

## Role Definitions

### Azure RBAC Roles


| # | RoleName | RoleDescription | RoleId |
|---|----------|-----------------|--------|
| 1 | `AcrDelete` | _acr delete_ | `c2f4ef07-c644-48eb-af81-4b1b4947fb11` |
| 2 | `AcrImageSigner` | _acr image signer_ | `6cef56e8-d556-48e5-a04f-b8e64114680f` |
| 3 | `AcrPull` | _acr pull_ | `7f951dda-4ed3-4680-a7ca-43fe172d538d` |
| 4 | `AcrPush` | _acr push_ | `8311e382-0749-4cb8-b61a-304f252e45ec` |
| 5 | `AcrQuarantineReader` | _acr quarantine data reader_ | `cdda3590-29a3-44f6-95f2-9f980659eb04` |
| 6 | `AcrQuarantineWriter` | _acr quarantine data writer_ | `c8d4ff99-41c3-41a8-9f60-21dfdad59608` |
| 7 | `AgFood Platform Service Admin` | _Provides admin access to AgFood Platform Service_ | `f8da80de-1ff9-4747-ad80-a19b7f6079e3` |
| 8 | `AgFood Platform Service Contributor` | _Provides contribute access to AgFood Platform Service_ | `8508508a-4469-4e45-963b-2518ee0bb728` |
| 9 | `AgFood Platform Service Reader` | _Provides read access to AgFood Platform Service_ | `7ec7ccdc-f61e-41fe-9aaf-980df0a44eba` |
| 10 | `AnyBuild Builder` | _Basic user role for AnyBuild. This role allows listing of agent information and execution of remote build capabilities._ | `a2138dac-4907-4679-a376-736901ed8ad8` |
| 11 | `API Management Service Contributor` | _Can manage service and the APIs_ | `312a565d-c81f-4fd8-895a-4e21e48d571c` |
| 12 | `API Management Service Operator Role` | _Can manage service but not the APIs_ | `e022efe7-f5ba-4159-bbe4-b44f577e9b61` |
| 13 | `API Management Service Reader Role` | _Read-only access to service and APIs_ | `71522526-b88f-4d52-b57f-d31fc3546d0d` |
| 14 | `App Configuration Data Owner` | _Allows full access to App Configuration data._ | `5ae67dd6-50cb-40e7-96ff-dc2bfa4b606b` |
| 15 | `App Configuration Data Reader` | _Allows read access to App Configuration data._ | `516239f1-63e1-4d78-a4de-a74fb236a071` |
| 16 | `Application Group Contributor` | _Contributor of the Application Group._ | `ca6382a4-1721-4bcf-a114-ff0c70227b6b` |
| 17 | `Application Insights Component Contributor` | _Can manage Application Insights components_ | `ae349356-3a1b-4a5e-921d-050484c6347e` |
| 18 | `Application Insights Snapshot Debugger` | _Gives user permission to use Application Insights Snapshot Debugger features_ | `08954f03-6346-4c2e-81c0-ec3a5cfae23b` |
| 19 | `Attestation Contributor` | _Can read write or delete the attestation provider instance_ | `bbf86eb8-f7b4-4cce-96e4-18cddf81d86e` |
| 20 | `Attestation Reader` | _Can read the attestation provider properties_ | `fd1bd22b-8476-40bc-a0bc-69b95687b9f3` |
| 21 | `Automation Contributor` | _Manage azure automation resources and other resources using azure automation._ | `f353d9bd-d4a6-484e-a77a-8050b599b867` |
| 22 | `Automation Job Operator` | _Create and Manage Jobs using Automation Runbooks._ | `4fe576fe-1146-4730-92eb-48519fa6bf9f` |
| 23 | `Automation Operator` | _Automation Operators are able to start, stop, suspend, and resume jobs_ | `d3881f73-407a-4167-8283-e981cbba0404` |
| 24 | `Automation Runbook Operator` | _Read Runbook properties - to be able to create Jobs of the runbook._ | `5fb5aef8-1081-4b8e-bb16-9d5d0385bab5` |
| 25 | `Autonomous Development Platform Data Contributor (Preview)` | _Grants permissions to upload and manage new Autonomous Development Platform measurements._ | `b8b15564-4fa6-4a59-ab12-03e1d9594795` |
| 26 | `Autonomous Development Platform Data Owner (Preview)` | _Grants full access to Autonomous Development Platform data._ | `27f8b550-c507-4db9-86f2-f4b8e816d59d` |
| 27 | `Autonomous Development Platform Data Reader (Preview)` | _Grants read access to Autonomous Development Platform data._ | `d63b75f7-47ea-4f27-92ac-e0d173aaf093` |
| 28 | `Avere Contributor` | _Can create and manage an Avere vFXT cluster._ | `4f8fab4f-1852-4a58-a46a-8eaf358af14a` |
| 29 | `Avere Operator` | _Used by the Avere vFXT cluster to manage the cluster_ | `c025889f-8102-4ebf-b32c-fc0c6f0c6bd9` |
| 30 | `Azure Arc Enabled Kubernetes Cluster User Role` | _List cluster user credentials action._ | `00493d72-78f6-4148-b6c5-d3ce8e4799dd` |
| 31 | `Azure Arc Kubernetes Admin` | _Lets you manage all resources under cluster/namespace, except update or delete resource quotas and namespaces._ | `dffb1e0c-446f-4dde-a09f-99eb5cc68b96` |
| 32 | `Azure Arc Kubernetes Cluster Admin` | _Lets you manage all resources in the cluster._ | `8393591c-06b9-48a2-a542-1bd6b377f6a2` |
| 33 | `Azure Arc Kubernetes Viewer` | _Lets you view all resources in cluster/namespace, except secrets._ | `63f0a09d-1495-4db4-a681-037d84835eb4` |
| 34 | `Azure Arc Kubernetes Writer` | _Lets you update everything in cluster/namespace, except (cluster)roles and (cluster)role bindings._ | `5b999177-9696-4545-85c7-50de3797e5a1` |
| 35 | `Azure Arc VMware Administrator role ` | _Arc VMware VM Contributor has permissions to perform all connected VMwarevSphere actions._ | `ddc140ed-e463-4246-9145-7c664192013f` |
| 36 | `Azure Arc VMware Private Cloud User` | _Azure Arc VMware Private Cloud User has permissions to use the VMware cloud resources to deploy VMs._ | `ce551c02-7c42-47e0-9deb-e3b6fc3a9a83` |
| 37 | `Azure Arc VMware Private Clouds Onboarding` | _Azure Arc VMware Private Clouds Onboarding role has permissions to provision all the required resources for onboard and deboard vCenter instances to Azure._ | `67d33e57-3129-45e6-bb0b-7cc522f762fa` |
| 38 | `Azure Arc VMware VM Contributor` | _Arc VMware VM Contributor has permissions to perform all VM actions._ | `b748a06d-6150-4f8a-aaa9-ce3940cd96cb` |
| 39 | `Azure Connected Machine Onboarding` | _Can onboard Azure Connected Machines._ | `b64e21ea-ac4e-4cdf-9dc9-5b892992bee7` |
| 40 | `Azure Connected Machine Resource Administrator` | _Can read, write, delete and re-onboard Azure Connected Machines._ | `cd570a14-e51a-42ad-bac8-bafd67325302` |
| 41 | `Azure Connected SQL Server Onboarding` | _Microsoft.AzureArcData service role to access the resources of Microsoft.AzureArcData stored with RPSAAS._ | `e8113dce-c529-4d33-91fa-e9b972617508` |
| 42 | `Azure Digital Twins Data Owner` | _Full access role for Digital Twins data-plane_ | `bcd981a7-7f74-457b-83e1-cceb9e632ffe` |
| 43 | `Azure Digital Twins Data Reader` | _Read-only role for Digital Twins data-plane properties_ | `d57506d4-4c8d-48b1-8587-93c323f6a5a3` |
| 44 | `Azure Event Hubs Data Owner` | _Allows for full access to Azure Event Hubs resources._ | `f526a384-b230-433a-b45c-95f59c4a2dec` |
| 45 | `Azure Event Hubs Data Receiver` | _Allows receive access to Azure Event Hubs resources._ | `a638d3c7-ab3a-418d-83e6-5f17a39d4fde` |
| 46 | `Azure Event Hubs Data Sender` | _Allows send access to Azure Event Hubs resources._ | `2b629674-e913-4c01-ae53-ef4638d8f975` |
| 47 | `Azure Kubernetes Service Cluster Admin Role` | _List cluster admin credential action._ | `0ab0b1a8-8aac-4efd-b8c2-3ee1fb270be8` |
| 48 | `Azure Kubernetes Service Cluster User Role` | _List cluster user credential action._ | `4abbcc35-e782-43d8-92c5-2d3f1bd2253f` |
| 49 | `Azure Kubernetes Service Contributor Role` | _Grants access to read and write Azure Kubernetes Service clusters_ | `ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8` |
| 50 | `Azure Kubernetes Service RBAC Admin` | _Lets you manage all resources under cluster/namespace, except update or delete resource quotas and namespaces._ | `3498e952-d568-435e-9b2c-8d77e338d7f7` |
| 51 | `Azure Kubernetes Service RBAC Cluster Admin` | _Lets you manage all resources in the cluster._ | `b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b` |
| 52 | `Azure Kubernetes Service RBAC Reader` | _Allows read-only access to see most objects in a namespace. It does not allow viewing roles or role bindings. This role does not allow viewing Secrets, since reading the contents of Secrets enables access to ServiceAccount credentials in the namespace, which would allow API access as any ServiceAccount in the namespace (a form of privilege escalation). Applying this role at cluster scope will give access across all namespaces._ | `7f6c6a51-bcf8-42ba-9220-52d62157d7db` |
| 53 | `Azure Kubernetes Service RBAC Writer` | _Allows read/write access to most objects in a namespace.This role does not allow viewing or modifying roles or role bindings. However, this role allows accessing Secrets and running Pods as any ServiceAccount in the namespace, so it can be used to gain the API access levels of any ServiceAccount in the namespace. Applying this role at cluster scope will give access across all namespaces._ | `a7ffa36f-339b-4b5c-8bdf-e2c188b2c0eb` |
| 54 | `Azure Maps Contributor` | _Grants access all Azure Maps resource management._ | `dba33070-676a-4fb0-87fa-064dc56ff7fb` |
| 55 | `Azure Maps Data Contributor` | _Grants access to read, write, and delete access to map related data from an Azure maps account._ | `8f5e0ce6-4f7b-4dcf-bddf-e6f48634a204` |
| 56 | `Azure Maps Data Reader` | _Grants access to read map related data from an Azure maps account._ | `423170ca-a8f6-4b0f-8487-9e4eb8f49bfa` |
| 57 | `Azure Maps Search and Render Data Reader` | _Grants access to very limited set of data APIs for common visual web SDK scenarios. Specifically, render and search data APIs._ | `6be48352-4f82-47c9-ad5e-0acacefdb005` |
| 58 | `Azure Relay Listener` | _Allows for listen access to Azure Relay resources._ | `26e0b698-aa6d-4085-9386-aadae190014d` |
| 59 | `Azure Relay Owner` | _Allows for full access to Azure Relay resources._ | `2787bf04-f1f5-4bfe-8383-c8a24483ee38` |
| 60 | `Azure Relay Sender` | _Allows for send access to Azure Relay resources._ | `26baccc8-eea7-41f1-98f4-1762cc7f685d` |
| 61 | `Azure Service Bus Data Owner` | _Allows for full access to Azure Service Bus resources._ | `090c5cfd-751d-490a-894a-3ce6f1109419` |
| 62 | `Azure Service Bus Data Receiver` | _Allows for receive access to Azure Service Bus resources._ | `4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0` |
| 63 | `Azure Service Bus Data Sender` | _Allows for send access to Azure Service Bus resources._ | `69a216fc-b8fb-44d8-bc22-1f3c2cd27a39` |
| 64 | `Azure Spring Cloud Config Server Contributor` | _Allow read, write and delete access to Azure Spring Cloud Config Server_ | `a06f5c24-21a7-4e1a-aa2b-f19eb6684f5b` |
| 65 | `Azure Spring Cloud Config Server Reader` | _Allow read access to Azure Spring Cloud Config Server_ | `d04c6db6-4947-4782-9e91-30a88feb7be7` |
| 66 | `Azure Spring Cloud Data Reader` | _Allow read access to Azure Spring Cloud Data_ | `b5537268-8956-4941-a8f0-646150406f0c` |
| 67 | `Azure Spring Cloud Service Registry Contributor` | _Allow read, write and delete access to Azure Spring Cloud Service Registry_ | `f5880b48-c26d-48be-b172-7927bfa1c8f1` |
| 68 | `Azure Spring Cloud Service Registry Reader` | _Allow read access to Azure Spring Cloud Service Registry_ | `cff1b556-2399-4e7e-856d-a8f754be7b65` |
| 69 | `Azure Stack Registration Owner` | _Lets you manage Azure Stack registrations._ | `6f12a6df-dd06-4f3e-bcb1-ce8be600526a` |
| 70 | `Azure VM Managed identities restore Contributor` | _Azure VM Managed identities restore Contributors are allowed to perform Azure VM Restores with managed identities both user and system_ | `6ae96244-5829-4925-a7d3-5975537d91dd` |
| 71 | `AzureML Data Scientist` | _Can perform all actions within an Azure Machine Learning workspace, except for creating or deleting compute resources and modifying the workspace itself._ | `f6c7c914-8db3-469d-8ca1-694a8f32e121` |
| 72 | `AzureML Metrics Writer (preview)` | _Lets you write metrics to AzureML workspace_ | `635dd51f-9968-44d3-b7fb-6d9a6bd613ae` |
| 73 | `Backup Contributor` | _Lets you manage backup service,but can't create vaults and give access to others_ | `5e467623-bb1f-42f4-a55d-6e525e11384b` |
| 74 | `Backup Operator` | _Lets you manage backup services, except removal of backup, vault creation and giving access to others_ | `00c29273-979b-4161-815c-10b084fb9324` |
| 75 | `Backup Reader` | _Can view backup services, but can't make changes_ | `a795c7a0-d4a2-40c1-ae25-d81f01202912` |
| 76 | `Billing Reader` | _Allows read access to billing data_ | `fa23ad8b-c56e-40d8-ac0c-ce449e1d2c64` |
| 77 | `BizTalk Contributor` | _Lets you manage BizTalk services, but not access to them._ | `5e3c6656-6cfa-4708-81fe-0de47ac73342` |
| 78 | `Blockchain Member Node Access (Preview)` | _Allows for access to Blockchain Member nodes_ | `31a002a1-acaf-453e-8a5b-297c9ca1ea24` |
| 79 | `Blueprint Contributor` | _Can manage blueprint definitions, but not assign them._ | `41077137-e803-4205-871c-5a86e6a753b4` |
| 80 | `Blueprint Operator` | _Can assign existing published blueprints, but cannot create new blueprints. NOTE: this only works if the assignment is done with a user-assigned managed identity._ | `437d2ced-4a38-4302-8479-ed2bcb43d090` |
| 81 | `CDN Endpoint Contributor` | _Can manage CDN endpoints, but can't grant access to other users._ | `426e0c7f-0c7e-4658-b36f-ff54d6c29b45` |
| 82 | `CDN Endpoint Reader` | _Can view CDN endpoints, but can't make changes._ | `871e35f6-b5c1-49cc-a043-bde969a0f2cd` |
| 83 | `CDN Profile Contributor` | _Can manage CDN profiles and their endpoints, but can't grant access to other users._ | `ec156ff8-a8d1-4d15-830c-5b80698ca432` |
| 84 | `CDN Profile Reader` | _Can view CDN profiles and their endpoints, but can't make changes._ | `8f96442b-4075-438f-813d-ad51ab4019af` |
| 85 | `Chamber Admin` | _Lets you manage everything under your HPC Workbench chamber._ | `4e9b8407-af2e-495b-ae54-bb60a55b1b5a` |
| 86 | `Chamber User` | _Lets you view everything under your HPC Workbench chamber, but not make any changes._ | `4447db05-44ed-4da3-ae60-6cbece780e32` |
| 87 | `Classic Network Contributor` | _Lets you manage classic networks, but not access to them._ | `b34d265f-36f7-4a0d-a4d4-e158ca92e90f` |
| 88 | `Classic Storage Account Contributor` | _Lets you manage classic storage accounts, but not access to them._ | `86e8f5dc-a6e9-4c67-9d15-de283e8eac25` |
| 89 | `Classic Storage Account Key Operator Service Role` | _Classic Storage Account Key Operators are allowed to list and regenerate keys on Classic Storage Accounts_ | `985d6b00-f706-48f5-a6fe-d0ca12fb668d` |
| 90 | `Classic Virtual Machine Contributor` | _Lets you manage classic virtual machines, but not access to them, and not the virtual network or storage account they're connected to._ | `d73bb868-a0df-4d4d-bd69-98a00b01fccb` |
| 91 | `ClearDB MySQL DB Contributor` | _Lets you manage ClearDB MySQL databases, but not access to them._ | `9106cda0-8a86-4e81-b686-29a22c54effe` |
| 92 | `CodeSigning Certificate Profile Signer` | _Sign files with a certificate profile. This role is in preview and subject to change._ | `2837e146-70d7-4cfd-ad55-7efa6464f958` |
| 93 | `Cognitive Services Contributor` | _Lets you create, read, update, delete and manage keys of Cognitive Services._ | `25fbc0a9-bd7c-42a3-aa1a-3b75d497ee68` |
| 94 | `Cognitive Services Custom Vision Contributor` | _Full access to the project, including the ability to view, create, edit, or delete projects._ | `c1ff6cc2-c111-46fe-8896-e0ef812ad9f3` |
| 95 | `Cognitive Services Custom Vision Deployment` | _Publish, unpublish or export models. Deployment can view the project but can't update._ | `5c4089e1-6d96-4d2f-b296-c1bc7137275f` |
| 96 | `Cognitive Services Custom Vision Labeler` | _View, edit training images and create, add, remove, or delete the image tags. Labelers can view the project but can't update anything other than training images and tags._ | `88424f51-ebe7-446f-bc41-7fa16989e96c` |
| 97 | `Cognitive Services Custom Vision Reader` | _Read-only actions in the project. Readers can't create or update the project._ | `93586559-c37d-4a6b-ba08-b9f0940c2d73` |
| 98 | `Cognitive Services Custom Vision Trainer` | _View, edit projects and train the models, including the ability to publish, unpublish, export the models. Trainers can't create or delete the project._ | `0a5ae4ab-0d65-4eeb-be61-29fc9b54394b` |
| 99 | `Cognitive Services Data Reader (Preview)` | _Lets you read Cognitive Services data._ | `b59867f0-fa02-499b-be73-45a86b5b3e1c` |
| 100 | `Cognitive Services Face Recognizer` | _Lets you perform detect, verify, identify, group, and find similar operations on Face API. This role does not allow create or delete operations, which makes it well suited for endpoints that only need inferencing capabilities, following 'least privilege' best practices._ | `9894cab4-e18a-44aa-828b-cb588cd6f2d7` |
| 101 | `Cognitive Services Immersive Reader User` | _Provides access to create Immersive Reader sessions and call APIs_ | `b2de6794-95db-4659-8781-7e080d3f2b9d` |
| 102 | `Cognitive Services Language Owner` | _Has access to all Read, Test, Write, Deploy and Delete functions under Language portal_ | `f07febfe-79bc-46b1-8b37-790e26e6e498` |
| 103 | `Cognitive Services Language Reader` | _Has access to Read and Test functions under Language portal_ | `7628b7b8-a8b2-4cdc-b46f-e9b35248918e` |
| 104 | `Cognitive Services Language Writer` | _ Has access to all Read, Test, and Write functions under Language Portal_ | `f2310ca1-dc64-4889-bb49-c8e0fa3d47a8` |
| 105 | `Cognitive Services LUIS Owner` | _ Has access to all Read, Test, Write, Deploy and Delete functions under LUIS_ | `f72c8140-2111-481c-87ff-72b910f6e3f8` |
| 106 | `Cognitive Services LUIS Reader` | _Has access to Read and Test functions under LUIS._ | `18e81cdc-4e98-4e29-a639-e7d10c5a6226` |
| 107 | `Cognitive Services LUIS Writer` | _Has access to all Read, Test, and Write functions under LUIS_ | `6322a993-d5c9-4bed-b113-e49bbea25b27` |
| 108 | `Cognitive Services Metrics Advisor Administrator` | _Full access to the project, including the system level configuration._ | `cb43c632-a144-4ec5-977c-e80c4affc34a` |
| 109 | `Cognitive Services Metrics Advisor User` | _Access to the project._ | `3b20f47b-3825-43cb-8114-4bd2201156a8` |
| 110 | `Cognitive Services QnA Maker Editor` | _Let's you create, edit, import and export a KB. You cannot publish or delete a KB._ | `f4cc2bf9-21be-47a1-bdf1-5c5804381025` |
| 111 | `Cognitive Services QnA Maker Reader` | _Let's you read and test a KB only._ | `466ccd10-b268-4a11-b098-b4849f024126` |
| 112 | `Cognitive Services Speech Contributor` | _Full access to Speech projects, including read, write and delete all entities, for real-time speech recognition and batch transcription tasks, real-time speech synthesis and long audio tasks, custom speech and custom voice._ | `0e75ca1e-0464-4b4d-8b93-68208a576181` |
| 113 | `Cognitive Services Speech User` | _Access to the real-time speech recognition and batch transcription APIs, real-time speech synthesis and long audio APIs, as well as to read the data/test/model/endpoint for custom models, but can't create, delete or modify the data/test/model/endpoint for custom models._ | `f2dc8367-1007-4938-bd23-fe263f013447` |
| 114 | `Cognitive Services User` | _Lets you read and list keys of Cognitive Services._ | `a97b65f3-24c7-4388-baec-2e87135dc908` |
| 115 | `Collaborative Data Contributor` | _Can manage data packages of a collaborative._ | `daa9e50b-21df-454c-94a6-a8050adab352` |
| 116 | `Collaborative Runtime Operator` | _Can manage resources created by AICS at runtime_ | `7a6f0e70-c033-4fb1-828c-08514e5f4102` |
| 117 | `Contributor` | _Grants full access to manage all resources, but does not allow you to assign roles in Azure RBAC, manage assignments in Azure Blueprints, or share image galleries._ | `b24988ac-6180-42a0-ab88-20f7382dd24c` |
| 118 | `Cosmos DB Account Reader Role` | _Can read Azure Cosmos DB Accounts data_ | `fbdf93bf-df7d-467e-a4d2-9458aa1360c8` |
| 119 | `Cosmos DB Operator` | _Lets you manage Azure Cosmos DB accounts, but not access data in them. Prevents access to account keys and connection strings._ | `230815da-be43-4aae-9cb4-875f7bd000aa` |
| 120 | `CosmosBackupOperator` | _Can submit restore request for a Cosmos DB database or a container for an account_ | `db7b14f2-5adf-42da-9f96-f2ee17bab5cb` |
| 121 | `CosmosRestoreOperator` | _Can perform restore action for Cosmos DB database account with continuous backup mode_ | `5432c526-bc82-444a-b7ba-57c5b0b5b34f` |
| 122 | `Cost Management Contributor` | _Can view costs and manage cost configuration (e.g. budgets, exports)_ | `434105ed-43f6-45c7-a02f-909b2ba83430` |
| 123 | `Cost Management Reader` | _Can view cost data and configuration (e.g. budgets, exports)_ | `72fafb9e-0641-4937-9268-a91bfd8191a3` |
| 124 | `Data Box Contributor` | _Lets you manage everything under Data Box Service except giving access to others._ | `add466c9-e687-43fc-8d98-dfcf8d720be5` |
| 125 | `Data Box Reader` | _Lets you manage Data Box Service except creating order or editing order details and giving access to others._ | `028f4ed7-e2a9-465e-a8f4-9c0ffdfdc027` |
| 126 | `Data Factory Contributor` | _Create and manage data factories, as well as child resources within them._ | `673868aa-7521-48a0-acc6-0f60742d39f5` |
| 127 | `Data Lake Analytics Developer` | _Lets you submit, monitor, and manage your own jobs but not create or delete Data Lake Analytics accounts._ | `47b7735b-770e-4598-a7da-8b91488b4c88` |
| 128 | `Data Purger` | _Can purge analytics data_ | `150f5e0c-0603-4f03-8c7f-cf70034c4e90` |
| 129 | `Desktop Virtualization Application Group Contributor` | _Contributor of the Desktop Virtualization Application Group._ | `86240b0e-9422-4c43-887b-b61143f32ba8` |
| 130 | `Desktop Virtualization Application Group Reader` | _Reader of the Desktop Virtualization Application Group._ | `aebf23d0-b568-4e86-b8f9-fe83a2c6ab55` |
| 131 | `Desktop Virtualization Contributor` | _Contributor of Desktop Virtualization._ | `082f0a83-3be5-4ba1-904c-961cca79b387` |
| 132 | `Desktop Virtualization Host Pool Contributor` | _Contributor of the Desktop Virtualization Host Pool._ | `e307426c-f9b6-4e81-87de-d99efb3c32bc` |
| 133 | `Desktop Virtualization Host Pool Reader` | _Reader of the Desktop Virtualization Host Pool._ | `ceadfde2-b300-400a-ab7b-6143895aa822` |
| 134 | `Desktop Virtualization Reader` | _Reader of Desktop Virtualization._ | `49a72310-ab8d-41df-bbb0-79b649203868` |
| 135 | `Desktop Virtualization Session Host Operator` | _Operator of the Desktop Virtualization Session Host._ | `2ad6aaab-ead9-4eaa-8ac5-da422f562408` |
| 136 | `Desktop Virtualization User` | _Allows user to use the applications in an application group._ | `1d18fff3-a72a-46b5-b4a9-0b38a3cd7e63` |
| 137 | `Desktop Virtualization User Session Operator` | _Operator of the Desktop Virtualization Uesr Session._ | `ea4bfff8-7fb4-485a-aadd-d4129a0ffaa6` |
| 138 | `Desktop Virtualization Workspace Contributor` | _Contributor of the Desktop Virtualization Workspace._ | `21efdde3-836f-432b-bf3d-3e8e734d4b2b` |
| 139 | `Desktop Virtualization Workspace Reader` | _Reader of the Desktop Virtualization Workspace._ | `0fa44ee9-7a7d-466b-9bb2-2bf446b1204d` |
| 140 | `Device Provisioning Service Data Contributor` | _Allows for full access to Device Provisioning Service data-plane operations._ | `dfce44e4-17b7-4bd1-a6d1-04996ec95633` |
| 141 | `Device Provisioning Service Data Reader` | _Allows for full read access to Device Provisioning Service data-plane properties._ | `10745317-c249-44a1-a5ce-3a4353c0bbd8` |
| 142 | `Device Update Administrator` | _Gives you full access to management and content operations_ | `02ca0879-e8e4-47a5-a61e-5c618b76e64a` |
| 143 | `Device Update Content Administrator` | _Gives you full access to content operations_ | `0378884a-3af5-44ab-8323-f5b22f9f3c98` |
| 144 | `Device Update Content Reader` | _Gives you read access to content operations, but does not allow making changes_ | `d1ee9a80-8b14-47f0-bdc2-f4a351625a7b` |
| 145 | `Device Update Deployments Administrator` | _Gives you full access to management operations_ | `e4237640-0e3d-4a46-8fda-70bc94856432` |
| 146 | `Device Update Deployments Reader` | _Gives you read access to management operations, but does not allow making changes_ | `49e2f5d2-7741-4835-8efa-19e1fe35e47f` |
| 147 | `Device Update Reader` | _Gives you read access to management and content operations, but does not allow making changes_ | `e9dba6fb-3d52-4cf0-bce3-f06ce71b9e0f` |
| 148 | `DevTest Labs User` | _Lets you connect, start, restart, and shutdown your virtual machines in your Azure DevTest Labs._ | `76283e04-6283-4c54-8f91-bcf1374a3c64` |
| 149 | `DICOM Data Owner` | _Full access to DICOM data._ | `58a3b984-7adf-4c20-983a-32417c86fbc8` |
| 150 | `DICOM Data Reader` | _Read and search DICOM data._ | `e89c7a3c-2f64-4fa1-a847-3e4c9ba4283a` |
| 151 | `Disk Backup Reader` | _Provides permission to backup vault to perform disk backup._ | `3e5e47e6-65f7-47ef-90b5-e5dd4d455f24` |
| 152 | `Disk Pool Operator` | _Used by the StoragePool Resource Provider to manage Disks added to a Disk Pool._ | `60fc6e62-5479-42d4-8bf4-67625fcc2840` |
| 153 | `Disk Restore Operator` | _Provides permission to backup vault to perform disk restore._ | `b50d9833-a0cb-478e-945f-707fcc997c13` |
| 154 | `Disk Snapshot Contributor` | _Provides permission to backup vault to manage disk snapshots._ | `7efff54f-a5b4-42b5-a1c5-5411624893ce` |
| 155 | `DNS Zone Contributor` | _Lets you manage DNS zones and record sets in Azure DNS, but does not let you control who has access to them._ | `befefa01-2a29-4197-83a8-272ff33ce314` |
| 156 | `DocumentDB Account Contributor` | _Lets you manage DocumentDB accounts, but not access to them._ | `5bd9cd88-fe45-4216-938b-f97437e15450` |
| 157 | `EventGrid Contributor` | _Lets you manage EventGrid operations._ | `1e241071-0855-49ea-94dc-649edcd759de` |
| 158 | `EventGrid Data Sender` | _Allows send access to event grid events._ | `d5a91429-5739-47e2-a06b-3470a27159e7` |
| 159 | `EventGrid EventSubscription Contributor` | _Lets you manage EventGrid event subscription operations._ | `428e0ff0-5e57-4d9c-a221-2c70d0e0a443` |
| 160 | `EventGrid EventSubscription Reader` | _Lets you read EventGrid event subscriptions._ | `2414bbcf-6497-4faf-8c65-045460748405` |
| 161 | `Experimentation Administrator` | _Experimentation Administrator_ | `7f646f1b-fa08-80eb-a33b-edd6ce5c915c` |
| 162 | `Experimentation Contributor` | _Experimentation Contributor_ | `7f646f1b-fa08-80eb-a22b-edd6ce5c915c` |
| 163 | `Experimentation Metric Contributor` | _Allows for creation, writes and reads to the metric set via the metrics service APIs._ | `6188b7c9-7d01-4f99-a59f-c88b630326c0` |
| 164 | `Experimentation Reader` | _Experimentation Reader_ | `49632ef5-d9ac-41f4-b8e7-bbe587fa74a1` |
| 165 | `FHIR Data Contributor` | _Role allows user or principal full access to FHIR Data_ | `5a1fc7df-4bf1-4951-a576-89034ee01acd` |
| 166 | `FHIR Data Converter` | _Role allows user or principal to convert data from legacy format to FHIR_ | `a1705bd2-3a8f-45a5-8683-466fcfd5cc24` |
| 167 | `FHIR Data Exporter` | _Role allows user or principal to read and export FHIR Data_ | `3db33094-8700-4567-8da5-1501d4e7e843` |
| 168 | `FHIR Data Reader` | _Role allows user or principal to read FHIR Data_ | `4c8d0bbc-75d3-4935-991f-5f3c56d81508` |
| 169 | `FHIR Data Writer` | _Role allows user or principal to read and write FHIR Data_ | `3f88fce4-5892-4214-ae73-ba5294559913` |
| 170 | `Grafana Admin` | _Built-in Grafana admin role_ | `22926164-76b3-42b3-bc55-97df8dab3e41` |
| 171 | `Grafana Editor` | _Built-in Grafana Editor role_ | `a79a5197-3a5c-4973-a920-486035ffd60f` |
| 172 | `Grafana Viewer` | _Built-in Grafana Viewer role_ | `60921a7e-fef1-4a43-9b16-a26c52ad4769` |
| 173 | `Graph Owner` | _Create and manage all aspects of the Enterprise Graph - Ontology, Schema mapping, Conflation and Conversational AI and Ingestions_ | `b60367af-1334-4454-b71e-769d9a4f83d9` |
| 174 | `Guest Configuration Resource Contributor` | _Grants access to read or write to Guest Configuration resources._ | `088ab73d-1256-47ae-bea9-9de8e7131f31` |
| 175 | `HDInsight Cluster Operator` | _Lets you read and modify HDInsight cluster configurations._ | `61ed4efc-fab3-44fd-b111-e24485cc132a` |
| 176 | `HDInsight Domain Services Contributor` | _Can Read, Create, Modify and Delete Domain Services related operations needed for HDInsight Enterprise Security Package_ | `8d8d5a11-05d3-4bda-a417-a08778121c7c` |
| 177 | `Hierarchy Settings Administrator` | _Allows users to edit and delete Hierarchy Settings_ | `350f8d15-c687-4448-8ae1-157740a3936d` |
| 178 | `Hybrid Server Onboarding` | _Can onboard new Hybrid servers to the Hybrid Resource Provider._ | `5d1e5ee4-7c68-4a71-ac8b-0739630a3dfb` |
| 179 | `Hybrid Server Resource Administrator` | _Can read, write, delete, and re-onboard Hybrid servers to the Hybrid Resource Provider._ | `48b40c6e-82e0-4eb3-90d5-19e40f49b624` |
| 180 | `Integration Service Environment Contributor` | _Lets you manage integration service environments, but not access to them._ | `a41e2c5b-bd99-4a07-88f4-9bf657a760b8` |
| 181 | `Integration Service Environment Developer` | _Allows developers to create and update workflows, integration accounts and API connections in integration service environments._ | `c7aa55d3-1abb-444a-a5ca-5e51e485d6ec` |
| 182 | `Intelligent Systems Account Contributor` | _Lets you manage Intelligent Systems accounts, but not access to them._ | `03a6d094-3444-4b3d-88af-7477090a9e5e` |
| 183 | `IoT Hub Data Contributor` | _Allows for full access to IoT Hub data plane operations._ | `4fc6c259-987e-4a07-842e-c321cc9d413f` |
| 184 | `IoT Hub Data Reader` | _Allows for full read access to IoT Hub data-plane properties_ | `b447c946-2db7-41ec-983d-d8bf3b1c77e3` |
| 185 | `IoT Hub Registry Contributor` | _Allows for full access to IoT Hub device registry._ | `4ea46cd5-c1b2-4a8e-910b-273211f9ce47` |
| 186 | `IoT Hub Twin Contributor` | _Allows for read and write access to all IoT Hub device and module twins._ | `494bdba2-168f-4f31-a0a1-191d2f7c028c` |
| 187 | `Key Vault Administrator` | _Perform all data plane operations on a key vault and all objects in it, including certificates, keys, and secrets. Cannot manage key vault resources or manage role assignments. Only works for key vaults that use the 'Azure role-based access control' permission model._ | `00482a5a-887f-4fb3-b363-3b7fe8e74483` |
| 188 | `Key Vault Certificates Officer` | _Perform any action on the certificates of a key vault, except manage permissions. Only works for key vaults that use the 'Azure role-based access control' permission model._ | `a4417e6f-fecd-4de8-b567-7b0420556985` |
| 189 | `Key Vault Contributor` | _Lets you manage key vaults, but not access to them._ | `f25e0fa2-a7c8-4377-a976-54943a77a395` |
| 190 | `Key Vault Crypto Officer` | _Perform any action on the keys of a key vault, except manage permissions. Only works for key vaults that use the 'Azure role-based access control' permission model._ | `14b46e9e-c2b7-41b4-b07b-48a6ebf60603` |
| 191 | `Key Vault Crypto Service Encryption User` | _Read metadata of keys and perform wrap/unwrap operations. Only works for key vaults that use the 'Azure role-based access control' permission model._ | `e147488a-f6f5-4113-8e2d-b22465e65bf6` |
| 192 | `Key Vault Crypto User` | _Perform cryptographic operations using keys. Only works for key vaults that use the 'Azure role-based access control' permission model._ | `12338af0-0e69-4776-bea7-57ae8d297424` |
| 193 | `Key Vault Reader` | _Read metadata of key vaults and its certificates, keys, and secrets. Cannot read sensitive values such as secret contents or key material. Only works for key vaults that use the 'Azure role-based access control' permission model._ | `21090545-7ca7-4776-b22c-e363652d74d2` |
| 194 | `Key Vault Secrets Officer` | _Perform any action on the secrets of a key vault, except manage permissions. Only works for key vaults that use the 'Azure role-based access control' permission model._ | `b86a8fe4-44ce-4948-aee5-eccb2c155cd7` |
| 195 | `Key Vault Secrets User` | _Read secret contents. Only works for key vaults that use the 'Azure role-based access control' permission model._ | `4633458b-17de-408a-b874-0445c86b69e6` |
| 196 | `Knowledge Consumer` | _Knowledge Read permission to consume Enterprise Graph Knowledge using entity search and graph query_ | `ee361c5d-f7b5-4119-b4b6-892157c8f64c` |
| 197 | `Kubernetes Cluster - Azure Arc Onboarding` | _Role definition to authorize any user/service to create connectedClusters resource_ | `34e09817-6cbe-4d01-b1a2-e0eac5743d41` |
| 198 | `Kubernetes Extension Contributor` | _Can create, update, get, list and delete Kubernetes Extensions, and get extension async operations_ | `85cb6faf-e071-4c9b-8136-154b5a04f717` |
| 199 | `Lab Assistant` | _The lab assistant role_ | `ce40b423-cede-4313-a93f-9b28290b72e1` |
| 200 | `Lab Contributor` | _The lab contributor role_ | `5daaa2af-1fe8-407c-9122-bba179798270` |
| 201 | `Lab Creator` | _Lets you create new labs under your Azure Lab Accounts._ | `b97fb8bc-a8b2-4522-a38b-dd33c7e65ead` |
| 202 | `Lab Operator` | _The lab operator role_ | `a36e6959-b6be-4b12-8e9f-ef4b474d304d` |
| 203 | `Lab Services Contributor` | _The lab services contributor role_ | `f69b8690-cc87-41d6-b77a-a4bc3c0a966f` |
| 204 | `Lab Services Reader` | _The lab services reader role_ | `2a5c394f-5eb7-4d4f-9c8e-e8eae39faebc` |
| 205 | `Load Test Contributor` | _View, create, update, delete and execute load tests. View and list load test resources but can not make any changes._ | `749a398d-560b-491b-bb21-08924219302e` |
| 206 | `Load Test Owner` | _Execute all operations on load test resources and load tests_ | `45bb0b16-2f0c-4e78-afaa-a07599b003f6` |
| 207 | `Load Test Reader` | _View and list all load tests and load test resources but can not make any changes_ | `3ae3fb29-0000-4ccd-bf80-542e7b26e081` |
| 208 | `Log Analytics Contributor` | _Log Analytics Contributor can read all monitoring data and edit monitoring settings. Editing monitoring settings includes adding the VM extension to VMs; reading storage account keys to be able to configure collection of logs from Azure Storage; adding solutions; and configuring Azure diagnostics on all Azure resources._ | `92aaf0da-9dab-42b6-94a3-d43ce8d16293` |
| 209 | `Log Analytics Reader` | _Log Analytics Reader can view and search all monitoring data as well as and view monitoring settings, including viewing the configuration of Azure diagnostics on all Azure resources._ | `73c42c96-874c-492b-b04d-ab87d138a893` |
| 210 | `Logic App Contributor` | _Lets you manage logic app, but not access to them._ | `87a39d53-fc1b-424a-814c-f7e04687dc9e` |
| 211 | `Logic App Operator` | _Lets you read, enable and disable logic app._ | `515c2055-d9d4-4321-b1b9-bd0c9a0f79fe` |
| 212 | `Managed Application Contributor Role` | _Allows for creating managed application resources._ | `641177b8-a67a-45b9-a033-47bc880bb21e` |
| 213 | `Managed Application Operator Role` | _Lets you read and perform actions on Managed Application resources_ | `c7393b34-138c-406f-901b-d8cf2b17e6ae` |
| 214 | `Managed Applications Reader` | _Lets you read resources in a managed app and request JIT access._ | `b9331d33-8a36-4f8c-b097-4f54124fdb44` |
| 215 | `Managed HSM contributor` | _Lets you manage managed HSM pools, but not access to them._ | `18500a29-7fe2-46b2-a342-b16a415e101d` |
| 216 | `Managed Identity Contributor` | _Create, Read, Update, and Delete User Assigned Identity_ | `e40ec5ca-96e0-45a2-b4ff-59039f2c2b59` |
| 217 | `Managed Identity Operator` | _Read and Assign User Assigned Identity_ | `f1a07417-d97a-45cb-824c-7a7467783830` |
| 218 | `Managed Services Registration assignment Delete Role` | _Managed Services Registration Assignment Delete Role allows the managing tenant users to delete the registration assignment assigned to their tenant._ | `91c1777a-f3dc-4fae-b103-61d183457e46` |
| 219 | `Management Group Contributor` | _Management Group Contributor Role_ | `5d58bcaf-24a5-4b20-bdb6-eed9f69fbe4c` |
| 220 | `Management Group Reader` | _Management Group Reader Role_ | `ac63b705-f282-497d-ac71-919bf39d939d` |
| 221 | `Media Services Account Administrator` | _Create, read, modify, and delete Media Services accounts; read-only access to other Media Services resources._ | `054126f8-9a2b-4f1c-a9ad-eca461f08466` |
| 222 | `Media Services Live Events Administrator` | _Create, read, modify, and delete Live Events, Assets, Asset Filters, and Streaming Locators; read-only access to other Media Services resources._ | `532bc159-b25e-42c0-969e-a1d439f60d77` |
| 223 | `Media Services Media Operator` | _Create, read, modify, and delete Assets, Asset Filters, Streaming Locators, and Jobs; read-only access to other Media Services resources._ | `e4395492-1534-4db2-bedf-88c14621589c` |
| 224 | `Media Services Policy Administrator` | _Create, read, modify, and delete Account Filters, Streaming Policies, Content Key Policies, and Transforms; read-only access to other Media Services resources. Cannot create Jobs, Assets or Streaming resources._ | `c4bba371-dacd-4a26-b320-7250bca963ae` |
| 225 | `Media Services Streaming Endpoints Administrator` | _Create, read, modify, and delete Streaming Endpoints; read-only access to other Media Services resources._ | `99dba123-b5fe-44d5-874c-ced7199a5804` |
| 226 | `Microsoft Sentinel Automation Contributor` | _Microsoft Sentinel Automation Contributor_ | `f4c81013-99ee-4d62-a7ee-b3f1f648599a` |
| 227 | `Microsoft Sentinel Contributor` | _Microsoft Sentinel Contributor_ | `ab8e14d6-4a74-4a29-9ba8-549422addade` |
| 228 | `Microsoft Sentinel Reader` | _Microsoft Sentinel Reader_ | `8d289c81-5878-46d4-8554-54e1e3d8b5cb` |
| 229 | `Microsoft Sentinel Responder` | _Microsoft Sentinel Responder_ | `3e150937-b8fe-4cfb-8069-0eaf05ecd056` |
| 230 | `Microsoft.Kubernetes connected cluster role` | _Microsoft.Kubernetes connected cluster role._ | `5548b2cf-c94c-4228-90ba-30851930a12f` |
| 231 | `Monitoring Contributor` | _Can read all monitoring data and update monitoring settings._ | `749f88d5-cbae-40b8-bcfc-e573ddc772fa` |
| 232 | `Monitoring Metrics Publisher` | _Enables publishing metrics against Azure resources_ | `3913510d-42f4-4e42-8a64-420c390055eb` |
| 233 | `Monitoring Reader` | _Can read all monitoring data._ | `43d0d8ad-25c7-4714-9337-8ba259a9fe05` |
| 234 | `Network Contributor` | _Lets you manage networks, but not access to them._ | `4d97b98b-1d4f-4787-a291-c67834d212e7` |
| 235 | `New Relic APM Account Contributor` | _Lets you manage New Relic Application Performance Management accounts and applications, but not access to them._ | `5d28c62d-5b37-4476-8438-e587778df237` |
| 236 | `Object Anchors Account Owner` | _Provides user with ingestion capabilities for an object anchors account._ | `ca0835dd-bacc-42dd-8ed2-ed5e7230d15b` |
| 237 | `Object Anchors Account Reader` | _Lets you read ingestion jobs for an object anchors account._ | `4a167cdf-cb95-4554-9203-2347fe489bd9` |
| 238 | `Object Understanding Account Owner` | _Provides user with ingestion capabilities for Azure Object Understanding._ | `4dd61c23-6743-42fe-a388-d8bdd41cb745` |
| 239 | `Object Understanding Account Reader` | _Lets you read ingestion jobs for an object understanding account._ | `d18777c0-1514-4662-8490-608db7d334b6` |
| 240 | `Owner` | _Grants full access to manage all resources, including the ability to assign roles in Azure RBAC._ | `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` |
| 241 | `PlayFab Contributor` | _Provides contributor access to PlayFab resources_ | `0c8b84dc-067c-4039-9615-fa1a4b77c726` |
| 242 | `PlayFab Reader` | _Provides read access to PlayFab resources_ | `a9a19cc5-31f4-447c-901f-56c0bb18fcaf` |
| 243 | `Policy Insights Data Writer (Preview)` | _Allows read access to resource policies and write access to resource component policy events._ | `66bb4e9e-b016-4a94-8249-4c0511c2be84` |
| 244 | `Private DNS Zone Contributor` | _Lets you manage private DNS zone resources, but not the virtual networks they are linked to._ | `b12aa53e-6015-4669-85d0-8515ebb3ae7f` |
| 245 | `Project Babylon Data Curator` | _The Microsoft.ProjectBabylon data curator can create, read, modify and delete catalog data objects and establish relationships between objects. This role is in preview and subject to change._ | `9ef4ef9c-a049-46b0-82ab-dd8ac094c889` |
| 246 | `Project Babylon Data Reader` | _The Microsoft.ProjectBabylon data reader can read catalog data objects. This role is in preview and subject to change._ | `c8d896ba-346d-4f50-bc1d-7d1c84130446` |
| 247 | `Project Babylon Data Source Administrator` | _The Microsoft.ProjectBabylon data source administrator can manage data sources and data scans. This role is in preview and subject to change._ | `05b7651b-dc44-475e-b74d-df3db49fae0f` |
| 248 | `Purview role 1 (Deprecated)` | _Deprecated role._ | `8a3c2885-9b38-4fd2-9d99-91af537c1347` |
| 249 | `Purview role 2 (Deprecated)` | _Deprecated role._ | `200bba9e-f0c8-430f-892b-6f0794863803` |
| 250 | `Purview role 3 (Deprecated)` | _Deprecated role._ | `ff100721-1b9d-43d8-af52-42b69c1272db` |
| 251 | `Quota Request Operator` | _Read and create quota requests, get quota request status, and create support tickets._ | `0e5f05e5-9ab9-446b-b98d-1e2157c94125` |
| 252 | `Reader` | _View all resources, but does not allow you to make any changes._ | `acdd72a7-3385-48ef-bd42-f606fba81ae7` |
| 253 | `Reader and Data Access` | _Lets you view everything but will not let you delete or create a storage account or contained resource. It will also allow read/write access to all data contained in a storage account via access to storage account keys._ | `c12c1c16-33a1-487b-954d-41c89c60f349` |
| 254 | `Redis Cache Contributor` | _Lets you manage Redis caches, but not access to them._ | `e0f68234-74aa-48ed-b826-c38b57376e17` |
| 255 | `Remote Rendering Administrator` | _Provides user with conversion, manage session, rendering and diagnostics capabilities for Azure Remote Rendering_ | `3df8b902-2a6f-47c7-8cc5-360e9b272a7e` |
| 256 | `Remote Rendering Client` | _Provides user with manage session, rendering and diagnostics capabilities for Azure Remote Rendering._ | `d39065c4-c120-43c9-ab0a-63eed9795f0a` |
| 257 | `Reservation Purchaser` | _Lets you purchase reservations_ | `f7b75c60-3036-4b75-91c3-6b41c27c1689` |
| 258 | `Resource Policy Contributor` | _Users with rights to create/modify resource policy, create support ticket and read resources/hierarchy._ | `36243c78-bf99-498c-9df9-86d9f8d28608` |
| 259 | `Scheduler Job Collections Contributor` | _Lets you manage Scheduler job collections, but not access to them._ | `188a0f2f-5c9e-469b-ae67-2aa5ce574b94` |
| 260 | `Schema Registry Contributor (Preview)` | _Read, write, and delete Schema Registry groups and schemas._ | `5dffeca3-4936-4216-b2bc-10343a5abb25` |
| 261 | `Schema Registry Reader (Preview)` | _Read and list Schema Registry groups and schemas._ | `2c56ea50-c6b3-40a6-83c0-9d98858bc7d2` |
| 262 | `Search Index Data Contributor` | _Grants full access to Azure Cognitive Search index data._ | `8ebe5a00-799e-43f5-93ac-243d3dce84a7` |
| 263 | `Search Index Data Reader` | _Grants read access to Azure Cognitive Search index data._ | `1407120a-92aa-4202-b7e9-c0e197c71c8f` |
| 264 | `Search Service Contributor` | _Lets you manage Search services, but not access to them._ | `7ca78c08-252a-4471-8644-bb5ff32d4ba0` |
| 265 | `Security Admin` | _Security Admin Role_ | `fb1c8493-542b-48eb-b624-b4c8fea62acd` |
| 266 | `Security Assessment Contributor` | _Lets you push assessments to Security Center_ | `612c2aa1-cb24-443b-ac28-3ab7272de6f5` |
| 267 | `Security Detonation Chamber Publisher` | _Allowed to publish and modify platforms, workflows and toolsets to Security Detonation Chamber_ | `352470b3-6a9c-4686-b503-35deb827e500` |
| 268 | `Security Detonation Chamber Reader` | _Allowed to query submission info and files from Security Detonation Chamber_ | `28241645-39f8-410b-ad48-87863e2951d5` |
| 269 | `Security Detonation Chamber Submission Manager` | _Allowed to create and manage submissions to Security Detonation Chamber_ | `a37b566d-3efa-4beb-a2f2-698963fa42ce` |
| 270 | `Security Detonation Chamber Submitter` | _Allowed to create submissions to Security Detonation Chamber_ | `0b555d9b-b4a7-4f43-b330-627f0e5be8f0` |
| 271 | `Security Manager (Legacy)` | _This is a legacy role. Please use Security Administrator instead_ | `e3d13bf0-dd5a-482e-ba6b-9b8433878d10` |
| 272 | `Security Reader` | _Security Reader Role_ | `39bc4728-0917-49c7-9d2c-d95423bc2eb4` |
| 273 | `Services Hub Operator` | _Services Hub Operator allows you to perform all read, write, and deletion operations related to Services Hub Connectors._ | `82200a5b-e217-47a5-b665-6d8765ee745b` |
| 274 | `SignalR AccessKey Reader` | _Read SignalR Service Access Keys_ | `04165923-9d83-45d5-8227-78b77b0a687e` |
| 275 | `SignalR App Server` | _Lets your app server access SignalR Service with AAD auth options._ | `420fcaa2-552c-430f-98ca-3264be4806c7` |
| 276 | `SignalR REST API Owner` | _Full access to Azure SignalR Service REST APIs_ | `fd53cd77-2268-407a-8f46-7e7863d0f521` |
| 277 | `SignalR REST API Reader` | _Read-only access to Azure SignalR Service REST APIs_ | `ddde6b66-c0df-4114-a159-3618637b3035` |
| 278 | `SignalR Service Owner` | _Full access to Azure SignalR Service REST APIs_ | `7e4f1700-ea5a-4f59-8f37-079cfe29dce3` |
| 279 | `SignalR/Web PubSub Contributor` | _Create, Read, Update, and Delete SignalR service resources_ | `8cf5e20a-e4b2-4e9d-b3a1-5ceb692c2761` |
| 280 | `Site Recovery Contributor` | _Lets you manage Site Recovery service except vault creation and role assignment_ | `6670b86e-a3f7-4917-ac9b-5d6ab1be4567` |
| 281 | `Site Recovery Operator` | _Lets you failover and failback but not perform other Site Recovery management operations_ | `494ae006-db33-4328-bf46-533a6560a3ca` |
| 282 | `Site Recovery Reader` | _Lets you view Site Recovery status but not perform other management operations_ | `dbaa88c4-0c30-4179-9fb3-46319faa6149` |
| 283 | `Spatial Anchors Account Contributor` | _Lets you manage spatial anchors in your account, but not delete them_ | `8bbe83f1-e2a6-4df7-8cb4-4e04d4e5c827` |
| 284 | `Spatial Anchors Account Owner` | _Lets you manage spatial anchors in your account, including deleting them_ | `70bbe301-9835-447d-afdd-19eb3167307c` |
| 285 | `Spatial Anchors Account Reader` | _Lets you locate and read properties of spatial anchors in your account_ | `5d51204f-eb77-4b1c-b86a-2ec626c49413` |
| 286 | `SQL DB Contributor` | _Lets you manage SQL databases, but not access to them. Also, you can't manage their security-related policies or their parent SQL servers._ | `9b7fa17d-e63e-47b0-bb0a-15c516ac86ec` |
| 287 | `SQL Managed Instance Contributor` | _Lets you manage SQL Managed Instances and required network configuration, but can't give access to others._ | `4939a1f6-9ae0-4e48-a1e0-f2cbe897382d` |
| 288 | `SQL Security Manager` | _Lets you manage the security-related policies of SQL servers and databases, but not access to them._ | `056cd41c-7e88-42e1-933e-88ba6a50c9c3` |
| 289 | `SQL Server Contributor` | _Lets you manage SQL servers and databases, but not access to them, and not their security -related policies._ | `6d8ee4ec-f05a-4a1d-8b00-a9b17e38b437` |
| 290 | `Storage Account Backup Contributor Role` | _Storage Account Backup Contributors are allowed to perform backup and restore of Storage Account._ | `e5e2a7ff-d759-4cd2-bb51-3152d37e2eb1` |
| 291 | `Storage Account Contributor` | _Lets you manage storage accounts, including accessing storage account keys which provide full access to storage account data._ | `17d1049b-9a84-46fb-8f53-869881c3d3ab` |
| 292 | `Storage Account Key Operator Service Role` | _Storage Account Key Operators are allowed to list and regenerate keys on Storage Accounts_ | `81a9662b-bebf-436f-a333-f67b29880f12` |
| 293 | `Storage Blob Data Contributor` | _Allows for read, write and delete access to Azure Storage blob containers and data_ | `ba92f5b4-2d11-453d-a403-e96b0029c9fe` |
| 294 | `Storage Blob Data Owner` | _Allows for full access to Azure Storage blob containers and data, including assigning POSIX access control._ | `b7e6dc6d-f1e8-4753-8033-0f276bb0955b` |
| 295 | `Storage Blob Data Reader` | _Allows for read access to Azure Storage blob containers and data_ | `2a2b9908-6ea1-4ae2-8e65-a410df84e7d1` |
| 296 | `Storage Blob Delegator` | _Allows for generation of a user delegation key which can be used to sign SAS tokens_ | `db58b8e5-c6ad-4a2a-8342-4190687cbf4a` |
| 297 | `Storage File Data SMB Share Contributor` | _Allows for read, write, and delete access in Azure Storage file shares over SMB_ | `0c867c2a-1d8c-454a-a3db-ab2ea1bdc8bb` |
| 298 | `Storage File Data SMB Share Elevated Contributor` | _Allows for read, write, delete and modify NTFS permission access in Azure Storage file shares over SMB_ | `a7264617-510b-434b-a828-9731dc254ea7` |
| 299 | `Storage File Data SMB Share Reader` | _Allows for read access to Azure File Share over SMB_ | `aba4ae5f-2193-4029-9191-0cb91df5e314` |
| 300 | `Storage Queue Data Contributor` | _Allows for read, write, and delete access to Azure Storage queues and queue messages_ | `974c5e8b-45b9-4653-ba55-5f855dd0fb88` |
| 301 | `Storage Queue Data Message Processor` | _Allows for peek, receive, and delete access to Azure Storage queue messages_ | `8a0f0c08-91a1-4084-bc3d-661d67233fed` |
| 302 | `Storage Queue Data Message Sender` | _Allows for sending of Azure Storage queue messages_ | `c6a89b2d-59bc-44d0-9896-0f6e12d7b80a` |
| 303 | `Storage Queue Data Reader` | _Allows for read access to Azure Storage queues and queue messages_ | `19e7f393-937e-4f77-808e-94535e297925` |
| 304 | `Storage Table Data Contributor` | _Allows for read, write and delete access to Azure Storage tables and entities_ | `0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3` |
| 305 | `Storage Table Data Reader` | _Allows for read access to Azure Storage tables and entities_ | `76199698-9eea-4c19-bc75-cec21354c6b6` |
| 306 | `Stream Analytics Query Tester` | _Lets you perform query testing without creating a stream analytics job first_ | `1ec5b3c1-b17e-4e25-8312-2acb3c3c5abf` |
| 307 | `Support Request Contributor` | _Lets you create and manage Support requests_ | `cfd33db0-3dd1-45e3-aa9d-cdbdf3b6f24e` |
| 308 | `Tag Contributor` | _Lets you manage tags on entities, without providing access to the entities themselves._ | `4a9ae827-6dc8-4573-8ac7-8239d42aa03f` |
| 309 | `Test Base Reader` | _Let you view and download packages and test results._ | `15e0f5a1-3450-4248-8e25-e2afe88a9e85` |
| 310 | `Traffic Manager Contributor` | _Lets you manage Traffic Manager profiles, but does not let you control who has access to them._ | `a4b10055-b0c7-44c2-b00f-c7b5b3550cf7` |
| 311 | `User Access Administrator` | _Lets you manage user access to Azure resources._ | `18d7d88d-d35e-4fb5-a5c3-7773c20a72d9` |
| 312 | `Virtual Machine Administrator Login` | _View Virtual Machines in the portal and login as administrator_ | `1c0163c0-47e6-4577-8991-ea5c82e286e4` |
| 313 | `Virtual Machine Contributor` | _Lets you manage virtual machines, but not access to them, and not the virtual network or storage account they're connected to._ | `9980e02c-c2be-4d73-94e8-173b1dc7cf3c` |
| 314 | `Virtual Machine User Login` | _View Virtual Machines in the portal and login as a regular user._ | `fb879df8-f326-4884-b1cf-06f3ad86be52` |
| 315 | `Web Plan Contributor` | _Lets you manage the web plans for websites, but not access to them._ | `2cc479cb-7b4d-49a8-b449-8c00fd0f0a4b` |
| 316 | `Web PubSub Service Owner (Preview)` | _Full access to Azure Web PubSub Service REST APIs_ | `12cf5a90-567b-43ae-8102-96cf46c7d9b4` |
| 317 | `Web PubSub Service Reader (Preview)` | _Read-only access to Azure Web PubSub Service REST APIs_ | `bfb1c7d2-fb1a-466b-b2ba-aee63b92deaf` |
| 318 | `Website Contributor` | _Lets you manage websites (not web plans), but not access to them._ | `de139f84-1756-47ae-9be6-808fbbe84772` |
| 319 | `Workbook Contributor` | _Can save shared workbooks._ | `e8ddcd69-c73f-4f9f-9844-4100522f16ad` |
| 320 | `Workbook Reader` | _Can read workbooks._ | `b279062a-9be3-42a0-92ae-8b3cf002ec4d` |
| 321 | `WorkloadBuilder Migration Agent Role` | _WorkloadBuilder Migration Agent Role._ | `d17ce0a2-0697-43bc-aac5-9113337ab61c` |

---

### Azure AD Roles

| # | RoleName | RoleDescription | RoleId |
|---|----------|-----------------|--------|
| 1 | `Application Administrator` | _Can create and manage all aspects of app registrations and enterprise apps._ | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` |
| 2 | `Application Developer` | _Can create application registrations independent of the 'Users can register applications' setting._ | `cf1c38e5-3621-4004-a7cb-879624dced7c` |
| 3 | `Attack Payload Author` | _Can create attack payloads that an administrator can initiate later._ | `9c6df0f2-1e7c-4dc3-b195-66dfbd24aa8f` |
| 4 | `Attack Simulation Administrator` | _Can create and manage all aspects of attack simulation campaigns._ | `c430b396-e693-46cc-96f3-db01bf8bb62a` |
| 5 | `Attribute Assignment Administrator` | _Assign custom security attribute keys and values to supported Azure AD objects._ | `58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d` |
| 6 | `Attribute Assignment Reader` | _Read custom security attribute keys and values for supported Azure AD objects._ | `ffd52fa5-98dc-465c-991d-fc073eb59f8f` |
| 7 | `Attribute Definition Administrator` | _Define and manage the definition of custom security attributes._ | `8424c6f0-a189-499e-bbd0-26c1753c96d4` |
| 8 | `Attribute Definition Reader` | _Read the definition of custom security attributes._ | `1d336d2c-4ae8-42ef-9711-b3604ce3fc2c` |
| 9 | `Authentication Administrator` | _Allowed to view, set and reset authentication method information for any non-admin user._ | `c4e39bd9-1100-46d3-8c65-fb160da0071f` |
| 10 | `Authentication Policy Administrator` | _Can create and manage the authentication methods policy, tenant-wide MFA settings, password protection policy, and verifiable credentials._ | `0526716b-113d-4c15-b2c8-68e3c22b9f80` |
| 11 | `Azure AD Joined Device Local Administrator` | _Users assigned to this role are added to the local administrators group on Azure AD-joined devices._ | `9f06204d-73c1-4d4c-880a-6edb90606fd8` |
| 12 | `Azure DevOps Administrator` | _Can manage Azure DevOps organization policy and settings._ | `e3973bdf-4987-49ae-837a-ba8e231c7286` |
| 13 | `Azure Information Protection Administrator` | _Can manage all aspects of the Azure Information Protection product._ | `7495fdc4-34c4-4d15-a289-98788ce399fd` |
| 14 | `B2C IEF Keyset Administrator` | _Can manage secrets for federation and encryption in the Identity Experience Framework (IEF)._ | `aaf43236-0c0d-4d5f-883a-6955382ac081` |
| 15 | `B2C IEF Policy Administrator` | _Can create and manage trust framework policies in the Identity Experience Framework (IEF)._ | `3edaf663-341e-4475-9f94-5c398ef6c070` |
| 16 | `Billing Administrator` | _Can perform common billing related tasks like updating payment information._ | `b0f54661-2d74-4c50-afa3-1ec803f12efe` |
| 17 | `Cloud App Security Administrator` | _Can manage all aspects of the Cloud App Security product._ | `892c5842-a9a6-463a-8041-72aa08ca3cf6` |
| 18 | `Cloud Application Administrator` | _Can create and manage all aspects of app registrations and enterprise apps except App Proxy._ | `158c047a-c907-4556-b7ef-446551a6b5f7` |
| 19 | `Cloud Device Administrator` | _Full access to manage devices in Azure AD._ | `7698a772-787b-4ac8-901f-60d6b08affd2` |
| 20 | `Compliance Administrator` | _Can read and manage compliance configuration and reports in Azure AD and Microsoft 365._ | `17315797-102d-40b4-93e0-432062caca18` |
| 21 | `Compliance Data Administrator` | _Creates and manages compliance content._ | `e6d1a23a-da11-4be4-9570-befc86d067a7` |
| 22 | `Conditional Access Administrator` | _Can manage Conditional Access capabilities._ | `b1be1c3e-b65d-4f19-8427-f6fa0d97feb9` |
| 23 | `Customer LockBox Access Approver` | _Can approve Microsoft support requests to access customer organizational data._ | `5c4f9dcd-47dc-4cf7-8c9a-9e4207cbfc91` |
| 24 | `Desktop Analytics Administrator` | _Can access and manage Desktop management tools and services._ | `38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4` |
| 25 | `Device Join` | _Device Join_ | `9c094953-4995-41c8-84c8-3ebb9b32c93f` |
| 26 | `Device Managers` | _Deprecated - Do Not Use._ | `2b499bcd-da44-4968-8aec-78e1674fa64d` |
| 27 | `Device Users` | _Device Users_ | `d405c6df-0af8-4e3b-95e4-4d06e542189e` |
| 28 | `Directory Readers` | _Can read basic directory information. Commonly used to grant directory read access to applications and guests._ | `88d8e3e3-8f55-4a1e-953a-9b9898b8876b` |
| 29 | `Directory Synchronization Accounts` | _Only used by Azure AD Connect service._ | `d29b2b05-8046-44ba-8758-1e26182fcf32` |
| 30 | `Directory Writers` | _Can read and write basic directory information. For granting access to applications, not intended for users._ | `9360feb5-f418-4baa-8175-e2a00bac4301` |
| 31 | `Domain Name Administrator` | _Can manage domain names in cloud and on-premises._ | `8329153b-31d0-4727-b945-745eb3bc5f31` |
| 32 | `Dynamics 365 Administrator` | _Can manage all aspects of the Dynamics 365 product._ | `44367163-eba1-44c3-98af-f5787879f96a` |
| 33 | `Edge Administrator` | _Manage all aspects of Microsoft Edge._ | `3f1acade-1e04-4fbc-9b69-f0302cd84aef` |
| 34 | `Exchange Administrator` | _Can manage all aspects of the Exchange product._ | `29232cdf-9323-42fd-ade2-1d097af3e4de` |
| 35 | `Exchange Recipient Administrator` | _Can create or update Exchange Online recipients within the Exchange Online organization._ | `31392ffb-586c-42d1-9346-e59415a2cc4e` |
| 36 | `External ID User Flow Administrator` | _Can create and manage all aspects of user flows._ | `6e591065-9bad-43ed-90f3-e9424366d2f0` |
| 37 | `External ID User Flow Attribute Administrator` | _Can create and manage the attribute schema available to all user flows._ | `0f971eea-41eb-4569-a71e-57bb8a3eff1e` |
| 38 | `External Identity Provider Administrator` | _Can configure identity providers for use in direct federation._ | `be2f45a1-457d-42af-a067-6ec1fa63bc45` |
| 39 | `Global Administrator` | _Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities._ | `62e90394-69f5-4237-9190-012177145e10` |
| 40 | `Global Reader` | _Can read everything that a Global Administrator can, but not update anything._ | `f2ef992c-3afb-46b9-b7cf-a126ee74c451` |
| 41 | `Groups Administrator` | _Members of this role can create/manage groups, create/manage groups settings like naming and expiration policies, and view groups activity and audit reports._ | `fdd7a751-b60b-444a-984c-02652fe8fa1c` |
| 42 | `Guest Inviter` | _Can invite guest users independent of the 'members can invite guests' setting._ | `95e79109-95c0-4d8e-aee3-d01accf2d47b` |
| 43 | `Guest User` | _Default role for guest users. Can read a limited set of directory information._ | `10dae51f-b6af-4016-8d66-8c2a99b929b3` |
| 44 | `Helpdesk Administrator` | _Can reset passwords for non-administrators and Helpdesk Administrators._ | `729827e3-9c14-49f7-bb1b-9608f156bbb8` |
| 45 | `Hybrid Identity Administrator` | _Can manage AD to Azure AD cloud provisioning, Azure AD Connect, and federation settings._ | `8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2` |
| 46 | `Identity Governance Administrator` | _Manage access using Azure AD for identity governance scenarios._ | `45d8d3c5-c802-45c6-b32a-1d70b5e1e86e` |
| 47 | `Insights Administrator` | _Has administrative access in the Microsoft 365 Insights app._ | `eb1f4a8d-243a-41f0-9fbd-c7cdf6c5ef7c` |
| 48 | `Insights Business Leader` | _Can view and share dashboards and insights via the M365 Insights app._ | `31e939ad-9672-4796-9c2e-873181342d2d` |
| 49 | `Intune Administrator` | _Can manage all aspects of the Intune product._ | `3a2c62db-5318-420d-8d74-23affee5d9d5` |
| 50 | `Kaizala Administrator` | _Can manage settings for Microsoft Kaizala._ | `74ef975b-6605-40af-a5d2-b9539d836353` |
| 51 | `Knowledge Administrator` | _Can configure knowledge, learning, and other intelligent features._ | `b5a8dcf3-09d5-43a9-a639-8e29ef291470` |
| 52 | `Knowledge Manager` | _Has access to topic management dashboard and can manage content._ | `744ec460-397e-42ad-a462-8b3f9747a02c` |
| 53 | `License Administrator` | _Can manage product licenses on users and groups._ | `4d6ac14f-3453-41d0-bef9-a3e0c569773a` |
| 54 | `Message Center Privacy Reader` | _Can read security messages and updates in Office 365 Message Center only._ | `ac16e43d-7b2d-40e0-ac05-243ff356ab5b` |
| 55 | `Message Center Reader` | _Can read messages and updates for their organization in Office 365 Message Center only._ | `790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b` |
| 56 | `Network Administrator` | _Can manage network locations and review enterprise network design insights for Microsoft 365 Software as a Service applications._ | `d37c8bed-0711-4417-ba38-b4abe66ce4c2` |
| 57 | `Office Apps Administrator` | _Can manage Office apps cloud services, including policy and settings management, and manage the ability to select, unselect and publish 'what's new' feature content to end-user's devices._ | `2b745bdf-0803-4d80-aa65-822c4493daac` |
| 58 | `Partner Tier1 Support` | _Do not use - not intended for general use._ | `4ba39ca4-527c-499a-b93d-d9b492c50246` |
| 59 | `Partner Tier2 Support` | _Do not use - not intended for general use._ | `e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8` |
| 60 | `Password Administrator` | _Can reset passwords for non-administrators and Password Administrators._ | `966707d0-3269-4727-9be2-8c3a10f19b9d` |
| 61 | `Power BI Administrator` | _Can manage all aspects of the Power BI product._ | `a9ea8996-122f-4c74-9520-8edcd192826c` |
| 62 | `Power Platform Administrator` | _Can create and manage all aspects of Microsoft Dynamics 365, PowerApps and Microsoft Flow._ | `11648597-926c-4cf3-9c36-bcebb0ba8dcc` |
| 63 | `Printer Administrator` | _Can manage all aspects of printers and printer connectors._ | `644ef478-e28f-4e28-b9dc-3fdde9aa0b1f` |
| 64 | `Printer Technician` | _Can manage all aspects of printers and printer connectors._ | `e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477` |
| 65 | `Privileged Authentication Administrator` | _Allowed to view, set and reset authentication method information for any user (admin or non-admin)._ | `7be44c8a-adaf-4e2a-84d6-ab2649e08a13` |
| 66 | `Privileged Role Administrator` | _Can manage role assignments in Azure AD, and all aspects of Privileged Identity Management._ | `e8611ab8-c189-46e8-94e1-60213ab1f814` |
| 67 | `Reports Reader` | _Can read sign-in and audit reports._ | `4a5d8f65-41da-4de4-8968-e035b65339cf` |
| 68 | `Restricted Guest User` | _Default role for guest users with restricted access. Can read a limited set of directory information._ | `2af84b1e-32c8-42b7-82bc-daa82404023b` |
| 69 | `Search Administrator` | _Can create and manage all aspects of Microsoft Search settings._ | `0964bb5e-9bdb-4d7b-ac29-58e794862a40` |
| 70 | `Search Editor` | _Can create and manage the editorial content such as bookmarks, Q and As, locations, floorplan._ | `8835291a-918c-4fd7-a9ce-faa49f0cf7d9` |
| 71 | `Security Administrator` | _Security Administrator allows ability to read and manage security configuration and reports._ | `194ae4cb-b126-40b2-bd5b-6091b380977d` |
| 72 | `Security Operator` | _Creates and manages security events._ | `5f2222b1-57c3-48ba-8ad5-d4759f1fde6f` |
| 73 | `Security Reader` | _Can read security information and reports in Azure AD and Office 365._ | `5d6b6bb7-de71-4623-b4af-96380a352509` |
| 74 | `Service Support Administrator` | _Can read service health information and manage support tickets._ | `f023fd81-a637-4b56-95fd-791ac0226033` |
| 75 | `SharePoint Administrator` | _Can manage all aspects of the SharePoint service._ | `f28a1f50-f6e7-4571-818b-6a12f2af6b6c` |
| 76 | `Skype for Business Administrator` | _Can manage all aspects of the Skype for Business product._ | `75941009-915a-4869-abe7-691bff18279e` |
| 77 | `Teams Administrator` | _Can manage the Microsoft Teams service._ | `69091246-20e8-4a56-aa4d-066075b2a7a8` |
| 78 | `Teams Communications Administrator` | _Can manage calling and meetings features within the Microsoft Teams service._ | `baf37b3a-610e-45da-9e62-d9d1e5e8914b` |
| 79 | `Teams Communications Support Engineer` | _Can troubleshoot communications issues within Teams using advanced tools._ | `f70938a0-fc10-4177-9e90-2178f8765737` |
| 80 | `Teams Communications Support Specialist` | _Can troubleshoot communications issues within Teams using basic tools._ | `fcf91098-03e3-41a9-b5ba-6f0ec8188a12` |
| 81 | `Teams Devices Administrator` | _Can perform management related tasks on Teams certified devices._ | `3d762c5a-1b6c-493f-843e-55a3b42923d4` |
| 82 | `Usage Summary Reports Reader` | _Can see only tenant level aggregates in Microsoft 365 Usage Analytics and Productivity Score._ | `75934031-6c7e-415a-99d7-48dbd49e875e` |
| 83 | `User` | _Default role for member users. Can read all and write a limited set of directory information._ | `a0b1b346-4d3e-4e8b-98f8-753987be4970` |
| 84 | `User Administrator` | _Can manage all aspects of users and groups, including resetting passwords for limited admins._ | `fe930be7-5e62-47db-91af-98c3a49a38b1` |
| 85 | `Windows 365 Administrator` | _Can provision and manage all aspects of Cloud PCs._ | `11451d60-acb2-45eb-a7d6-43d0f0125c13` |
| 86 | `Windows Update Deployment Administrator` | _Can create and manage all aspects of Windows Update deployments through the Windows Update for Business deployment service._ | `32696413-001a-46ae-978c-ce0f6b3620d2` |
| 87 | `Workplace Device Join` | _Workplace Device Join_ | `c34f683f-4d5a-4403-affd-6615e00e3a7f` |

--- 

## Role Permissions

This section contains detailed definitions of each role along with their assigned permissions sets.

### Azure RBAC Role Permissions


---

#### `AcrDelete`


- Actions:
  - `Microsoft.ContainerRegistry/registries/artifacts/delete`


---

#### `AcrImageSigner`


- Actions:
  - `Microsoft.ContainerRegistry/registries/sign/write`

- DataActions:
  - `Microsoft.ContainerRegistry/registries/trustedCollections/write`


---

#### `AcrPull`


- Actions:
  - `Microsoft.ContainerRegistry/registries/pull/read`


---

#### `AcrPush`


- Actions:
  - `Microsoft.ContainerRegistry/registries/pull/read`
  - `Microsoft.ContainerRegistry/registries/push/write`


---

#### `AcrQuarantineReader`


- Actions:
  - `Microsoft.ContainerRegistry/registries/quarantine/read`

- DataActions:
  - `Microsoft.ContainerRegistry/registries/quarantinedArtifacts/read`


---

#### `AcrQuarantineWriter`


- Actions:
  - `Microsoft.ContainerRegistry/registries/quarantine/read`
  - `Microsoft.ContainerRegistry/registries/quarantine/write`

- DataActions:
  - `Microsoft.ContainerRegistry/registries/quarantinedArtifacts/read`
  - `Microsoft.ContainerRegistry/registries/quarantinedArtifacts/write`


---

#### `AgFood Platform Service Admin`


- DataActions:
  - `Microsoft.AgFoodPlatform/*`


---

#### `AgFood Platform Service Contributor`


- DataActions:
  - `Microsoft.AgFoodPlatform/*/action`
  - `Microsoft.AgFoodPlatform/*/read`
  - `Microsoft.AgFoodPlatform/*/write`

- NotDataActions:
  - `Microsoft.AgFoodPlatform/farmers/write`
  - `Microsoft.AgFoodPlatform/deletionJobs/*/write`


---

#### `AgFood Platform Service Reader`


- DataActions:
  - `Microsoft.AgFoodPlatform/*/read`


---

#### `AnyBuild Builder`


- DataActions:
  - `Microsoft.AnyBuild/clusters/build/write`
  - `Microsoft.AnyBuild/clusters/build/read`


---

#### `API Management Service Contributor`


- Actions:
  - `Microsoft.ApiManagement/service/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `API Management Service Operator Role`


- Actions:
  - `Microsoft.ApiManagement/service/*/read`
  - `Microsoft.ApiManagement/service/backup/action`
  - `Microsoft.ApiManagement/service/delete`
  - `Microsoft.ApiManagement/service/managedeployments/action`
  - `Microsoft.ApiManagement/service/read`
  - `Microsoft.ApiManagement/service/restore/action`
  - `Microsoft.ApiManagement/service/updatecertificate/action`
  - `Microsoft.ApiManagement/service/updatehostname/action`
  - `Microsoft.ApiManagement/service/write`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- NotActions:
  - `Microsoft.ApiManagement/service/users/keys/read`


---

#### `API Management Service Reader Role`


- Actions:
  - `Microsoft.ApiManagement/service/*/read`
  - `Microsoft.ApiManagement/service/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- NotActions:
  - `Microsoft.ApiManagement/service/users/keys/read`


---

#### `App Configuration Data Owner`


- DataActions:
  - `Microsoft.AppConfiguration/configurationStores/*/read`
  - `Microsoft.AppConfiguration/configurationStores/*/write`
  - `Microsoft.AppConfiguration/configurationStores/*/delete`


---

#### `App Configuration Data Reader`


- DataActions:
  - `Microsoft.AppConfiguration/configurationStores/*/read`


---

#### `Application Group Contributor`


- Actions:
  - `Microsoft.DesktopVirtualization/applicationgroups/*`
  - `Microsoft.DesktopVirtualization/hostpools/read`
  - `Microsoft.DesktopVirtualization/hostpools/sessionhosts/read`
  - `Microsoft.DesktopVirtualization/workspaces/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Support/*`


---

#### `Application Insights Component Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/generateLiveToken/read`
  - `Microsoft.Insights/metricAlerts/*`
  - `Microsoft.Insights/components/*`
  - `Microsoft.Insights/scheduledqueryrules/*`
  - `Microsoft.Insights/topology/read`
  - `Microsoft.Insights/transactions/read`
  - `Microsoft.Insights/webtests/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Application Insights Snapshot Debugger`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/components/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Attestation Contributor`


- Actions:
  - `Microsoft.Attestation/attestationProviders/attestation/read`
  - `Microsoft.Attestation/attestationProviders/attestation/write`
  - `Microsoft.Attestation/attestationProviders/attestation/delete`


---

#### `Attestation Reader`


- Actions:
  - `Microsoft.Attestation/attestationProviders/attestation/read`


---

#### `Automation Contributor`


- Actions:
  - `Microsoft.Automation/automationAccounts/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Insights/ActionGroups/*`
  - `Microsoft.Insights/ActivityLogAlerts/*`
  - `Microsoft.Insights/MetricAlerts/*`
  - `Microsoft.Insights/ScheduledQueryRules/*`
  - `Microsoft.Insights/diagnosticSettings/*`
  - `Microsoft.OperationalInsights/workspaces/sharedKeys/action`


---

#### `Automation Job Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/read`
  - `Microsoft.Automation/automationAccounts/jobs/read`
  - `Microsoft.Automation/automationAccounts/jobs/resume/action`
  - `Microsoft.Automation/automationAccounts/jobs/stop/action`
  - `Microsoft.Automation/automationAccounts/jobs/streams/read`
  - `Microsoft.Automation/automationAccounts/jobs/suspend/action`
  - `Microsoft.Automation/automationAccounts/jobs/write`
  - `Microsoft.Automation/automationAccounts/jobs/output/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Automation Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/read`
  - `Microsoft.Automation/automationAccounts/jobs/read`
  - `Microsoft.Automation/automationAccounts/jobs/resume/action`
  - `Microsoft.Automation/automationAccounts/jobs/stop/action`
  - `Microsoft.Automation/automationAccounts/jobs/streams/read`
  - `Microsoft.Automation/automationAccounts/jobs/suspend/action`
  - `Microsoft.Automation/automationAccounts/jobs/write`
  - `Microsoft.Automation/automationAccounts/jobSchedules/read`
  - `Microsoft.Automation/automationAccounts/jobSchedules/write`
  - `Microsoft.Automation/automationAccounts/linkedWorkspace/read`
  - `Microsoft.Automation/automationAccounts/read`
  - `Microsoft.Automation/automationAccounts/runbooks/read`
  - `Microsoft.Automation/automationAccounts/schedules/read`
  - `Microsoft.Automation/automationAccounts/schedules/write`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Automation/automationAccounts/jobs/output/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Automation Runbook Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Automation/automationAccounts/runbooks/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Autonomous Development Platform Data Contributor (Preview)`


- Actions:
  - `Microsoft.AutonomousDevelopmentPlatform/*/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`

- DataActions:
  - `Microsoft.AutonomousDevelopmentPlatform/accounts/dataPools/discoveries/*`
  - `Microsoft.AutonomousDevelopmentPlatform/accounts/dataPools/uploads/*`
  - `Microsoft.AutonomousDevelopmentPlatform/accounts/dataPools/measurements/states/new/*`
  - `Microsoft.AutonomousDevelopmentPlatform/accounts/dataPools/measurementCollections/*`
  - `Microsoft.AutonomousDevelopmentPlatform/accounts/measurementCollections/*`
  - `Microsoft.AutonomousDevelopmentPlatform/workspaces/discoveries/*`
  - `Microsoft.AutonomousDevelopmentPlatform/workspaces/uploads/*`
  - `Microsoft.AutonomousDevelopmentPlatform/workspaces/measurements/states/new/*`
  - `Microsoft.AutonomousDevelopmentPlatform/workspaces/measurementCollections/*`

- NotDataActions:
  - `Microsoft.AutonomousDevelopmentPlatform/accounts/dataPools/measurements/states/new/changeState/action`
  - `Microsoft.AutonomousDevelopmentPlatform/workspaces/measurements/states/new/changeState/action`


---

#### `Autonomous Development Platform Data Owner (Preview)`


- Actions:
  - `Microsoft.AutonomousDevelopmentPlatform/*/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`

- DataActions:
  - `Microsoft.AutonomousDevelopmentPlatform/*`


---

#### `Autonomous Development Platform Data Reader (Preview)`


- Actions:
  - `Microsoft.AutonomousDevelopmentPlatform/*/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`

- DataActions:
  - `Microsoft.AutonomousDevelopmentPlatform/*/read`


---

#### `Avere Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Compute/*/read`
  - `Microsoft.Compute/availabilitySets/*`
  - `Microsoft.Compute/proximityPlacementGroups/*`
  - `Microsoft.Compute/virtualMachines/*`
  - `Microsoft.Compute/disks/*`
  - `Microsoft.Network/*/read`
  - `Microsoft.Network/networkInterfaces/*`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.Network/virtualNetworks/subnets/read`
  - `Microsoft.Network/virtualNetworks/subnets/join/action`
  - `Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action`
  - `Microsoft.Network/networkSecurityGroups/join/action`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/*/read`
  - `Microsoft.Storage/storageAccounts/*`
  - `Microsoft.Support/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/resources/read`

- DataActions:
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write`


---

#### `Avere Operator`


- Actions:
  - `Microsoft.Compute/virtualMachines/read`
  - `Microsoft.Network/networkInterfaces/read`
  - `Microsoft.Network/networkInterfaces/write`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.Network/virtualNetworks/subnets/read`
  - `Microsoft.Network/virtualNetworks/subnets/join/action`
  - `Microsoft.Network/networkSecurityGroups/join/action`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/delete`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/read`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/write`

- DataActions:
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write`


---

#### `Azure Arc Enabled Kubernetes Cluster User Role`


- Actions:
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Kubernetes/connectedClusters/listClusterUserCredentials/action`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Support/*`


---

#### `Azure Arc Kubernetes Admin`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- DataActions:
  - `Microsoft.Kubernetes/connectedClusters/apps/controllerrevisions/read`
  - `Microsoft.Kubernetes/connectedClusters/apps/daemonsets/*`
  - `Microsoft.Kubernetes/connectedClusters/apps/deployments/*`
  - `Microsoft.Kubernetes/connectedClusters/apps/replicasets/*`
  - `Microsoft.Kubernetes/connectedClusters/apps/statefulsets/*`
  - `Microsoft.Kubernetes/connectedClusters/authorization.k8s.io/localsubjectaccessreviews/write`
  - `Microsoft.Kubernetes/connectedClusters/autoscaling/horizontalpodautoscalers/*`
  - `Microsoft.Kubernetes/connectedClusters/batch/cronjobs/*`
  - `Microsoft.Kubernetes/connectedClusters/batch/jobs/*`
  - `Microsoft.Kubernetes/connectedClusters/configmaps/*`
  - `Microsoft.Kubernetes/connectedClusters/endpoints/*`
  - `Microsoft.Kubernetes/connectedClusters/events.k8s.io/events/read`
  - `Microsoft.Kubernetes/connectedClusters/events/read`
  - `Microsoft.Kubernetes/connectedClusters/extensions/daemonsets/*`
  - `Microsoft.Kubernetes/connectedClusters/extensions/deployments/*`
  - `Microsoft.Kubernetes/connectedClusters/extensions/ingresses/*`
  - `Microsoft.Kubernetes/connectedClusters/extensions/networkpolicies/*`
  - `Microsoft.Kubernetes/connectedClusters/extensions/replicasets/*`
  - `Microsoft.Kubernetes/connectedClusters/limitranges/read`
  - `Microsoft.Kubernetes/connectedClusters/namespaces/read`
  - `Microsoft.Kubernetes/connectedClusters/networking.k8s.io/ingresses/*`
  - `Microsoft.Kubernetes/connectedClusters/networking.k8s.io/networkpolicies/*`
  - `Microsoft.Kubernetes/connectedClusters/persistentvolumeclaims/*`
  - `Microsoft.Kubernetes/connectedClusters/pods/*`
  - `Microsoft.Kubernetes/connectedClusters/policy/poddisruptionbudgets/*`
  - `Microsoft.Kubernetes/connectedClusters/rbac.authorization.k8s.io/rolebindings/*`
  - `Microsoft.Kubernetes/connectedClusters/rbac.authorization.k8s.io/roles/*`
  - `Microsoft.Kubernetes/connectedClusters/replicationcontrollers/*`
  - `Microsoft.Kubernetes/connectedClusters/replicationcontrollers/*`
  - `Microsoft.Kubernetes/connectedClusters/resourcequotas/read`
  - `Microsoft.Kubernetes/connectedClusters/secrets/*`
  - `Microsoft.Kubernetes/connectedClusters/serviceaccounts/*`
  - `Microsoft.Kubernetes/connectedClusters/services/*`


---

#### `Azure Arc Kubernetes Cluster Admin`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- DataActions:
  - `Microsoft.Kubernetes/connectedClusters/*`


---

#### `Azure Arc Kubernetes Viewer`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- DataActions:
  - `Microsoft.Kubernetes/connectedClusters/apps/controllerrevisions/read`
  - `Microsoft.Kubernetes/connectedClusters/apps/daemonsets/read`
  - `Microsoft.Kubernetes/connectedClusters/apps/deployments/read`
  - `Microsoft.Kubernetes/connectedClusters/apps/replicasets/read`
  - `Microsoft.Kubernetes/connectedClusters/apps/statefulsets/read`
  - `Microsoft.Kubernetes/connectedClusters/autoscaling/horizontalpodautoscalers/read`
  - `Microsoft.Kubernetes/connectedClusters/batch/cronjobs/read`
  - `Microsoft.Kubernetes/connectedClusters/batch/jobs/read`
  - `Microsoft.Kubernetes/connectedClusters/configmaps/read`
  - `Microsoft.Kubernetes/connectedClusters/endpoints/read`
  - `Microsoft.Kubernetes/connectedClusters/events.k8s.io/events/read`
  - `Microsoft.Kubernetes/connectedClusters/events/read`
  - `Microsoft.Kubernetes/connectedClusters/extensions/daemonsets/read`
  - `Microsoft.Kubernetes/connectedClusters/extensions/deployments/read`
  - `Microsoft.Kubernetes/connectedClusters/extensions/ingresses/read`
  - `Microsoft.Kubernetes/connectedClusters/extensions/networkpolicies/read`
  - `Microsoft.Kubernetes/connectedClusters/extensions/replicasets/read`
  - `Microsoft.Kubernetes/connectedClusters/limitranges/read`
  - `Microsoft.Kubernetes/connectedClusters/namespaces/read`
  - `Microsoft.Kubernetes/connectedClusters/networking.k8s.io/ingresses/read`
  - `Microsoft.Kubernetes/connectedClusters/networking.k8s.io/networkpolicies/read`
  - `Microsoft.Kubernetes/connectedClusters/persistentvolumeclaims/read`
  - `Microsoft.Kubernetes/connectedClusters/pods/read`
  - `Microsoft.Kubernetes/connectedClusters/policy/poddisruptionbudgets/read`
  - `Microsoft.Kubernetes/connectedClusters/replicationcontrollers/read`
  - `Microsoft.Kubernetes/connectedClusters/replicationcontrollers/read`
  - `Microsoft.Kubernetes/connectedClusters/resourcequotas/read`
  - `Microsoft.Kubernetes/connectedClusters/serviceaccounts/read`
  - `Microsoft.Kubernetes/connectedClusters/services/read`


---

#### `Azure Arc Kubernetes Writer`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- DataActions:
  - `Microsoft.Kubernetes/connectedClusters/apps/controllerrevisions/read`
  - `Microsoft.Kubernetes/connectedClusters/apps/daemonsets/*`
  - `Microsoft.Kubernetes/connectedClusters/apps/deployments/*`
  - `Microsoft.Kubernetes/connectedClusters/apps/replicasets/*`
  - `Microsoft.Kubernetes/connectedClusters/apps/statefulsets/*`
  - `Microsoft.Kubernetes/connectedClusters/autoscaling/horizontalpodautoscalers/*`
  - `Microsoft.Kubernetes/connectedClusters/batch/cronjobs/*`
  - `Microsoft.Kubernetes/connectedClusters/batch/jobs/*`
  - `Microsoft.Kubernetes/connectedClusters/configmaps/*`
  - `Microsoft.Kubernetes/connectedClusters/endpoints/*`
  - `Microsoft.Kubernetes/connectedClusters/events.k8s.io/events/read`
  - `Microsoft.Kubernetes/connectedClusters/events/read`
  - `Microsoft.Kubernetes/connectedClusters/extensions/daemonsets/*`
  - `Microsoft.Kubernetes/connectedClusters/extensions/deployments/*`
  - `Microsoft.Kubernetes/connectedClusters/extensions/ingresses/*`
  - `Microsoft.Kubernetes/connectedClusters/extensions/networkpolicies/*`
  - `Microsoft.Kubernetes/connectedClusters/extensions/replicasets/*`
  - `Microsoft.Kubernetes/connectedClusters/limitranges/read`
  - `Microsoft.Kubernetes/connectedClusters/namespaces/read`
  - `Microsoft.Kubernetes/connectedClusters/networking.k8s.io/ingresses/*`
  - `Microsoft.Kubernetes/connectedClusters/networking.k8s.io/networkpolicies/*`
  - `Microsoft.Kubernetes/connectedClusters/persistentvolumeclaims/*`
  - `Microsoft.Kubernetes/connectedClusters/pods/*`
  - `Microsoft.Kubernetes/connectedClusters/policy/poddisruptionbudgets/*`
  - `Microsoft.Kubernetes/connectedClusters/replicationcontrollers/*`
  - `Microsoft.Kubernetes/connectedClusters/replicationcontrollers/*`
  - `Microsoft.Kubernetes/connectedClusters/resourcequotas/read`
  - `Microsoft.Kubernetes/connectedClusters/secrets/*`
  - `Microsoft.Kubernetes/connectedClusters/serviceaccounts/*`
  - `Microsoft.Kubernetes/connectedClusters/services/*`


---

#### `Azure Arc VMware Administrator role `


- Actions:
  - `Microsoft.ConnectedVMwarevSphere/*`
  - `Microsoft.Insights/AlertRules/Write`
  - `Microsoft.Insights/AlertRules/Delete`
  - `Microsoft.Insights/AlertRules/Read`
  - `Microsoft.Insights/AlertRules/Activated/Action`
  - `Microsoft.Insights/AlertRules/Resolved/Action`
  - `Microsoft.Insights/AlertRules/Throttled/Action`
  - `Microsoft.Insights/AlertRules/Incidents/Read`
  - `Microsoft.Resources/deployments/read`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/deployments/delete`
  - `Microsoft.Resources/deployments/cancel/action`
  - `Microsoft.Resources/deployments/validate/action`
  - `Microsoft.Resources/deployments/whatIf/action`
  - `Microsoft.Resources/deployments/exportTemplate/action`
  - `Microsoft.Resources/deployments/operations/read`
  - `Microsoft.Resources/deployments/operationstatuses/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/write`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/operations/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/operationstatuses/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/subscriptions/operationresults/read`


---

#### `Azure Arc VMware Private Cloud User`


- Actions:
  - `Microsoft.Insights/AlertRules/Write`
  - `Microsoft.Insights/AlertRules/Delete`
  - `Microsoft.Insights/AlertRules/Read`
  - `Microsoft.Insights/AlertRules/Activated/Action`
  - `Microsoft.Insights/AlertRules/Resolved/Action`
  - `Microsoft.Insights/AlertRules/Throttled/Action`
  - `Microsoft.Insights/AlertRules/Incidents/Read`
  - `Microsoft.Resources/deployments/read`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/deployments/delete`
  - `Microsoft.Resources/deployments/cancel/action`
  - `Microsoft.Resources/deployments/validate/action`
  - `Microsoft.Resources/deployments/whatIf/action`
  - `Microsoft.Resources/deployments/exportTemplate/action`
  - `Microsoft.Resources/deployments/operations/read`
  - `Microsoft.Resources/deployments/operationstatuses/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/write`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/operations/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/operationstatuses/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.ConnectedVMwarevSphere/virtualnetworks/join/action`
  - `Microsoft.ConnectedVMwarevSphere/virtualnetworks/Read`
  - `Microsoft.ConnectedVMwarevSphere/virtualmachinetemplates/clone/action`
  - `Microsoft.ConnectedVMwarevSphere/virtualmachinetemplates/Read`
  - `Microsoft.ConnectedVMwarevSphere/resourcepools/deploy/action`
  - `Microsoft.ConnectedVMwarevSphere/resourcepools/Read`
  - `Microsoft.ConnectedVMwarevSphere/hosts/deploy/action`
  - `Microsoft.ConnectedVMwarevSphere/hosts/Read`
  - `Microsoft.ConnectedVMwarevSphere/clusters/deploy/action`
  - `Microsoft.ConnectedVMwarevSphere/clusters/Read`
  - `Microsoft.ConnectedVMwarevSphere/datastores/allocateSpace/action`
  - `Microsoft.ConnectedVMwarevSphere/datastores/Read`


---

#### `Azure Arc VMware Private Clouds Onboarding`


- Actions:
  - `Microsoft.ConnectedVMwarevSphere/vcenters/Write`
  - `Microsoft.ConnectedVMwarevSphere/vcenters/Read`
  - `Microsoft.ConnectedVMwarevSphere/vcenters/Delete`
  - `Microsoft.Insights/AlertRules/Write`
  - `Microsoft.Insights/AlertRules/Delete`
  - `Microsoft.Insights/AlertRules/Read`
  - `Microsoft.Insights/AlertRules/Activated/Action`
  - `Microsoft.Insights/AlertRules/Resolved/Action`
  - `Microsoft.Insights/AlertRules/Throttled/Action`
  - `Microsoft.Insights/AlertRules/Incidents/Read`
  - `Microsoft.Resources/deployments/read`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/deployments/delete`
  - `Microsoft.Resources/deployments/cancel/action`
  - `Microsoft.Resources/deployments/validate/action`
  - `Microsoft.Resources/deployments/whatIf/action`
  - `Microsoft.Resources/deployments/exportTemplate/action`
  - `Microsoft.Resources/deployments/operations/read`
  - `Microsoft.Resources/deployments/operationstatuses/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/write`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/operations/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/operationstatuses/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.KubernetesConfiguration/extensions/Write`
  - `Microsoft.KubernetesConfiguration/extensions/Read`
  - `Microsoft.KubernetesConfiguration/extensions/Delete`
  - `Microsoft.KubernetesConfiguration/operations/read`
  - `Microsoft.ExtendedLocation/customLocations/Read`
  - `Microsoft.ExtendedLocation/customLocations/Write`
  - `Microsoft.ExtendedLocation/customLocations/Delete`
  - `Microsoft.ExtendedLocation/customLocations/deploy/action`
  - `Microsoft.ResourceConnector/appliances/Read`
  - `Microsoft.ResourceConnector/appliances/Write`
  - `Microsoft.ResourceConnector/appliances/Delete`


---

#### `Azure Arc VMware VM Contributor`


- Actions:
  - `Microsoft.ConnectedVMwarevSphere/virtualmachines/*`
  - `Microsoft.Insights/AlertRules/Write`
  - `Microsoft.Insights/AlertRules/Delete`
  - `Microsoft.Insights/AlertRules/Read`
  - `Microsoft.Insights/AlertRules/Activated/Action`
  - `Microsoft.Insights/AlertRules/Resolved/Action`
  - `Microsoft.Insights/AlertRules/Throttled/Action`
  - `Microsoft.Insights/AlertRules/Incidents/Read`
  - `Microsoft.Resources/deployments/read`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/deployments/delete`
  - `Microsoft.Resources/deployments/cancel/action`
  - `Microsoft.Resources/deployments/validate/action`
  - `Microsoft.Resources/deployments/whatIf/action`
  - `Microsoft.Resources/deployments/exportTemplate/action`
  - `Microsoft.Resources/deployments/operations/read`
  - `Microsoft.Resources/deployments/operationstatuses/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/write`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/operations/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/operationstatuses/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/subscriptions/operationresults/read`


---

#### `Azure Connected Machine Onboarding`


- Actions:
  - `Microsoft.HybridCompute/machines/read`
  - `Microsoft.HybridCompute/machines/write`
  - `Microsoft.HybridCompute/privateLinkScopes/read`
  - `Microsoft.GuestConfiguration/guestConfigurationAssignments/read`


---

#### `Azure Connected Machine Resource Administrator`


- Actions:
  - `Microsoft.HybridCompute/machines/read`
  - `Microsoft.HybridCompute/machines/write`
  - `Microsoft.HybridCompute/machines/delete`
  - `Microsoft.HybridCompute/machines/UpgradeExtensions/action`
  - `Microsoft.HybridCompute/machines/extensions/read`
  - `Microsoft.HybridCompute/machines/extensions/write`
  - `Microsoft.HybridCompute/machines/extensions/delete`
  - `Microsoft.HybridCompute/privateLinkScopes/*`
  - `Microsoft.HybridCompute/*/read`
  - `Microsoft.Resources/deployments/*`


---

#### `Azure Connected SQL Server Onboarding`


- Actions:
  - `Microsoft.AzureArcData/sqlServerInstances/read`
  - `Microsoft.AzureArcData/sqlServerInstances/write`


---

#### `Azure Digital Twins Data Owner`


- DataActions:
  - `Microsoft.DigitalTwins/eventroutes/*`
  - `Microsoft.DigitalTwins/digitaltwins/*`
  - `Microsoft.DigitalTwins/digitaltwins/commands/*`
  - `Microsoft.DigitalTwins/digitaltwins/relationships/*`
  - `Microsoft.DigitalTwins/models/*`
  - `Microsoft.DigitalTwins/query/*`


---

#### `Azure Digital Twins Data Reader`


- DataActions:
  - `Microsoft.DigitalTwins/digitaltwins/read`
  - `Microsoft.DigitalTwins/digitaltwins/relationships/read`
  - `Microsoft.DigitalTwins/eventroutes/read`
  - `Microsoft.DigitalTwins/models/read`
  - `Microsoft.DigitalTwins/query/action`


---

#### `Azure Event Hubs Data Owner`


- Actions:
  - `Microsoft.EventHub/*`

- DataActions:
  - `Microsoft.EventHub/*`


---

#### `Azure Event Hubs Data Receiver`


- Actions:
  - `Microsoft.EventHub/*/eventhubs/consumergroups/read`

- DataActions:
  - `Microsoft.EventHub/*/receive/action`


---

#### `Azure Event Hubs Data Sender`


- Actions:
  - `Microsoft.EventHub/*/eventhubs/read`

- DataActions:
  - `Microsoft.EventHub/*/send/action`


---

#### `Azure Kubernetes Service Cluster Admin Role`


- Actions:
  - `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action`
  - `Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action`
  - `Microsoft.ContainerService/managedClusters/read`


---

#### `Azure Kubernetes Service Cluster User Role`


- Actions:
  - `Microsoft.ContainerService/managedClusters/listClusterUserCredential/action`
  - `Microsoft.ContainerService/managedClusters/read`


---

#### `Azure Kubernetes Service Contributor Role`


- Actions:
  - `Microsoft.ContainerService/managedClusters/read`
  - `Microsoft.ContainerService/managedClusters/write`
  - `Microsoft.Resources/deployments/*`


---

#### `Azure Kubernetes Service RBAC Admin`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.ContainerService/managedClusters/listClusterUserCredential/action`

- DataActions:
  - `Microsoft.ContainerService/managedClusters/*`

- NotDataActions:
  - `Microsoft.ContainerService/managedClusters/resourcequotas/write`
  - `Microsoft.ContainerService/managedClusters/resourcequotas/delete`
  - `Microsoft.ContainerService/managedClusters/namespaces/write`
  - `Microsoft.ContainerService/managedClusters/namespaces/delete`


---

#### `Azure Kubernetes Service RBAC Cluster Admin`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.ContainerService/managedClusters/listClusterUserCredential/action`

- DataActions:
  - `Microsoft.ContainerService/managedClusters/*`


---

#### `Azure Kubernetes Service RBAC Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- DataActions:
  - `Microsoft.ContainerService/managedClusters/apps/controllerrevisions/read`
  - `Microsoft.ContainerService/managedClusters/apps/daemonsets/read`
  - `Microsoft.ContainerService/managedClusters/apps/deployments/read`
  - `Microsoft.ContainerService/managedClusters/apps/replicasets/read`
  - `Microsoft.ContainerService/managedClusters/apps/statefulsets/read`
  - `Microsoft.ContainerService/managedClusters/autoscaling/horizontalpodautoscalers/read`
  - `Microsoft.ContainerService/managedClusters/batch/cronjobs/read`
  - `Microsoft.ContainerService/managedClusters/batch/jobs/read`
  - `Microsoft.ContainerService/managedClusters/configmaps/read`
  - `Microsoft.ContainerService/managedClusters/endpoints/read`
  - `Microsoft.ContainerService/managedClusters/events.k8s.io/events/read`
  - `Microsoft.ContainerService/managedClusters/events/read`
  - `Microsoft.ContainerService/managedClusters/extensions/daemonsets/read`
  - `Microsoft.ContainerService/managedClusters/extensions/deployments/read`
  - `Microsoft.ContainerService/managedClusters/extensions/ingresses/read`
  - `Microsoft.ContainerService/managedClusters/extensions/networkpolicies/read`
  - `Microsoft.ContainerService/managedClusters/extensions/replicasets/read`
  - `Microsoft.ContainerService/managedClusters/limitranges/read`
  - `Microsoft.ContainerService/managedClusters/namespaces/read`
  - `Microsoft.ContainerService/managedClusters/networking.k8s.io/ingresses/read`
  - `Microsoft.ContainerService/managedClusters/networking.k8s.io/networkpolicies/read`
  - `Microsoft.ContainerService/managedClusters/persistentvolumeclaims/read`
  - `Microsoft.ContainerService/managedClusters/pods/read`
  - `Microsoft.ContainerService/managedClusters/policy/poddisruptionbudgets/read`
  - `Microsoft.ContainerService/managedClusters/replicationcontrollers/read`
  - `Microsoft.ContainerService/managedClusters/replicationcontrollers/read`
  - `Microsoft.ContainerService/managedClusters/resourcequotas/read`
  - `Microsoft.ContainerService/managedClusters/serviceaccounts/read`
  - `Microsoft.ContainerService/managedClusters/services/read`


---

#### `Azure Kubernetes Service RBAC Writer`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- DataActions:
  - `Microsoft.ContainerService/managedClusters/apps/controllerrevisions/read`
  - `Microsoft.ContainerService/managedClusters/apps/daemonsets/*`
  - `Microsoft.ContainerService/managedClusters/apps/deployments/*`
  - `Microsoft.ContainerService/managedClusters/apps/replicasets/*`
  - `Microsoft.ContainerService/managedClusters/apps/statefulsets/*`
  - `Microsoft.ContainerService/managedClusters/autoscaling/horizontalpodautoscalers/*`
  - `Microsoft.ContainerService/managedClusters/batch/cronjobs/*`
  - `Microsoft.ContainerService/managedClusters/batch/jobs/*`
  - `Microsoft.ContainerService/managedClusters/configmaps/*`
  - `Microsoft.ContainerService/managedClusters/endpoints/*`
  - `Microsoft.ContainerService/managedClusters/events.k8s.io/events/read`
  - `Microsoft.ContainerService/managedClusters/events/read`
  - `Microsoft.ContainerService/managedClusters/extensions/daemonsets/*`
  - `Microsoft.ContainerService/managedClusters/extensions/deployments/*`
  - `Microsoft.ContainerService/managedClusters/extensions/ingresses/*`
  - `Microsoft.ContainerService/managedClusters/extensions/networkpolicies/*`
  - `Microsoft.ContainerService/managedClusters/extensions/replicasets/*`
  - `Microsoft.ContainerService/managedClusters/limitranges/read`
  - `Microsoft.ContainerService/managedClusters/namespaces/read`
  - `Microsoft.ContainerService/managedClusters/networking.k8s.io/ingresses/*`
  - `Microsoft.ContainerService/managedClusters/networking.k8s.io/networkpolicies/*`
  - `Microsoft.ContainerService/managedClusters/persistentvolumeclaims/*`
  - `Microsoft.ContainerService/managedClusters/pods/*`
  - `Microsoft.ContainerService/managedClusters/policy/poddisruptionbudgets/*`
  - `Microsoft.ContainerService/managedClusters/replicationcontrollers/*`
  - `Microsoft.ContainerService/managedClusters/replicationcontrollers/*`
  - `Microsoft.ContainerService/managedClusters/resourcequotas/read`
  - `Microsoft.ContainerService/managedClusters/secrets/*`
  - `Microsoft.ContainerService/managedClusters/serviceaccounts/*`
  - `Microsoft.ContainerService/managedClusters/services/*`


---

#### `Azure Maps Contributor`


- Actions:
  - `Microsoft.Maps/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`


---

#### `Azure Maps Data Contributor`


- DataActions:
  - `Microsoft.Maps/accounts/*/read`
  - `Microsoft.Maps/accounts/*/write`
  - `Microsoft.Maps/accounts/*/delete`
  - `Microsoft.Maps/accounts/*/action`


---

#### `Azure Maps Data Reader`


- DataActions:
  - `Microsoft.Maps/accounts/*/read`


---

#### `Azure Maps Search and Render Data Reader`


- DataActions:
  - `Microsoft.Maps/accounts/services/render/read`
  - `Microsoft.Maps/accounts/services/search/read`


---

#### `Azure Relay Listener`


- Actions:
  - `Microsoft.Relay/*/wcfRelays/read`
  - `Microsoft.Relay/*/hybridConnections/read`

- DataActions:
  - `Microsoft.Relay/*/listen/action`


---

#### `Azure Relay Owner`


- Actions:
  - `Microsoft.Relay/*`

- DataActions:
  - `Microsoft.Relay/*`


---

#### `Azure Relay Sender`


- Actions:
  - `Microsoft.Relay/*/wcfRelays/read`
  - `Microsoft.Relay/*/hybridConnections/read`

- DataActions:
  - `Microsoft.Relay/*/send/action`


---

#### `Azure Service Bus Data Owner`


- Actions:
  - `Microsoft.ServiceBus/*`

- DataActions:
  - `Microsoft.ServiceBus/*`


---

#### `Azure Service Bus Data Receiver`


- Actions:
  - `Microsoft.ServiceBus/*/queues/read`
  - `Microsoft.ServiceBus/*/topics/read`
  - `Microsoft.ServiceBus/*/topics/subscriptions/read`

- DataActions:
  - `Microsoft.ServiceBus/*/receive/action`


---

#### `Azure Service Bus Data Sender`


- Actions:
  - `Microsoft.ServiceBus/*/queues/read`
  - `Microsoft.ServiceBus/*/topics/read`
  - `Microsoft.ServiceBus/*/topics/subscriptions/read`

- DataActions:
  - `Microsoft.ServiceBus/*/send/action`


---

#### `Azure Spring Cloud Config Server Contributor`


- DataActions:
  - `Microsoft.AppPlatform/Spring/configService/read`
  - `Microsoft.AppPlatform/Spring/configService/write`
  - `Microsoft.AppPlatform/Spring/configService/delete`


---

#### `Azure Spring Cloud Config Server Reader`


- DataActions:
  - `Microsoft.AppPlatform/Spring/configService/read`


---

#### `Azure Spring Cloud Data Reader`


- DataActions:
  - `Microsoft.AppPlatform/Spring/*/read`


---

#### `Azure Spring Cloud Service Registry Contributor`


- DataActions:
  - `Microsoft.AppPlatform/Spring/eurekaService/read`
  - `Microsoft.AppPlatform/Spring/eurekaService/write`
  - `Microsoft.AppPlatform/Spring/eurekaService/delete`


---

#### `Azure Spring Cloud Service Registry Reader`


- DataActions:
  - `Microsoft.AppPlatform/Spring/eurekaService/read`


---

#### `Azure Stack Registration Owner`


- Actions:
  - `Microsoft.AzureStack/edgeSubscriptions/read`
  - `Microsoft.AzureStack/registrations/products/*/action`
  - `Microsoft.AzureStack/registrations/products/read`
  - `Microsoft.AzureStack/registrations/read`


---

#### `Azure VM Managed identities restore Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`


---

#### `AzureML Data Scientist`


- Actions:
  - `Microsoft.MachineLearningServices/workspaces/*/read`
  - `Microsoft.MachineLearningServices/workspaces/*/action`
  - `Microsoft.MachineLearningServices/workspaces/*/delete`
  - `Microsoft.MachineLearningServices/workspaces/*/write`

- NotActions:
  - `Microsoft.MachineLearningServices/workspaces/delete`
  - `Microsoft.MachineLearningServices/workspaces/write`
  - `Microsoft.MachineLearningServices/workspaces/computes/*/write`
  - `Microsoft.MachineLearningServices/workspaces/computes/*/delete`
  - `Microsoft.MachineLearningServices/workspaces/computes/listKeys/action`
  - `Microsoft.MachineLearningServices/workspaces/listKeys/action`


---

#### `AzureML Metrics Writer (preview)`


- Actions:
  - `Microsoft.MachineLearningServices/workspaces/metrics/*/write`


---

#### `Backup Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.RecoveryServices/locations/*`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/operationResults/*`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/*`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/refreshContainers/action`
  - `Microsoft.RecoveryServices/Vaults/backupJobs/*`
  - `Microsoft.RecoveryServices/Vaults/backupJobsExport/action`
  - `Microsoft.RecoveryServices/Vaults/backupOperationResults/*`
  - `Microsoft.RecoveryServices/Vaults/backupPolicies/*`
  - `Microsoft.RecoveryServices/Vaults/backupProtectableItems/*`
  - `Microsoft.RecoveryServices/Vaults/backupProtectedItems/*`
  - `Microsoft.RecoveryServices/Vaults/backupProtectionContainers/*`
  - `Microsoft.RecoveryServices/Vaults/backupSecurityPIN/*`
  - `Microsoft.RecoveryServices/Vaults/backupUsageSummaries/read`
  - `Microsoft.RecoveryServices/Vaults/certificates/*`
  - `Microsoft.RecoveryServices/Vaults/extendedInformation/*`
  - `Microsoft.RecoveryServices/Vaults/monitoringAlerts/read`
  - `Microsoft.RecoveryServices/Vaults/monitoringConfigurations/*`
  - `Microsoft.RecoveryServices/Vaults/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/*`
  - `Microsoft.RecoveryServices/Vaults/usages/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/storageAccounts/read`
  - `Microsoft.RecoveryServices/Vaults/backupstorageconfig/*`
  - `Microsoft.RecoveryServices/Vaults/backupconfig/*`
  - `Microsoft.RecoveryServices/Vaults/backupValidateOperation/action`
  - `Microsoft.RecoveryServices/Vaults/write`
  - `Microsoft.RecoveryServices/Vaults/backupOperations/read`
  - `Microsoft.RecoveryServices/Vaults/backupEngines/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/backupProtectionIntent/*`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectableContainers/read`
  - `Microsoft.RecoveryServices/locations/backupStatus/action`
  - `Microsoft.RecoveryServices/locations/backupPreValidateProtection/action`
  - `Microsoft.RecoveryServices/locations/backupValidateFeatures/action`
  - `Microsoft.RecoveryServices/Vaults/monitoringAlerts/write`
  - `Microsoft.RecoveryServices/operations/read`
  - `Microsoft.RecoveryServices/locations/operationStatus/read`
  - `Microsoft.RecoveryServices/Vaults/backupProtectionIntents/read`
  - `Microsoft.Support/*`
  - `Microsoft.DataProtection/locations/getBackupStatus/action`
  - `Microsoft.DataProtection/backupVaults/backupInstances/write`
  - `Microsoft.DataProtection/backupVaults/backupInstances/delete`
  - `Microsoft.DataProtection/backupVaults/backupInstances/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/backup/action`
  - `Microsoft.DataProtection/backupVaults/backupInstances/validateRestore/action`
  - `Microsoft.DataProtection/backupVaults/backupInstances/restore/action`
  - `Microsoft.DataProtection/backupVaults/backupPolicies/write`
  - `Microsoft.DataProtection/backupVaults/backupPolicies/delete`
  - `Microsoft.DataProtection/backupVaults/backupPolicies/read`
  - `Microsoft.DataProtection/backupVaults/backupPolicies/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/recoveryPoints/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/recoveryPoints/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/findRestorableTimeRanges/action`
  - `Microsoft.DataProtection/backupVaults/write`
  - `Microsoft.DataProtection/backupVaults/read`
  - `Microsoft.DataProtection/backupVaults/operationResults/read`
  - `Microsoft.DataProtection/locations/checkNameAvailability/action`
  - `Microsoft.DataProtection/backupVaults/read`
  - `Microsoft.DataProtection/backupVaults/read`
  - `Microsoft.DataProtection/locations/operationStatus/read`
  - `Microsoft.DataProtection/locations/operationResults/read`
  - `Microsoft.DataProtection/backupVaults/validateForBackup/action`
  - `Microsoft.DataProtection/providers/operations/read`


---

#### `Backup Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/backup/action`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/operationsStatus/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/provisionInstantItemRecovery/action`
  - `Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/accessToken/action`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/restore/action`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/revokeInstantItemRecovery/action`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/write`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/refreshContainers/action`
  - `Microsoft.RecoveryServices/Vaults/backupJobs/*`
  - `Microsoft.RecoveryServices/Vaults/backupJobsExport/action`
  - `Microsoft.RecoveryServices/Vaults/backupOperationResults/*`
  - `Microsoft.RecoveryServices/Vaults/backupPolicies/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupPolicies/read`
  - `Microsoft.RecoveryServices/Vaults/backupProtectableItems/*`
  - `Microsoft.RecoveryServices/Vaults/backupProtectedItems/read`
  - `Microsoft.RecoveryServices/Vaults/backupProtectionContainers/read`
  - `Microsoft.RecoveryServices/Vaults/backupUsageSummaries/read`
  - `Microsoft.RecoveryServices/Vaults/certificates/write`
  - `Microsoft.RecoveryServices/Vaults/extendedInformation/read`
  - `Microsoft.RecoveryServices/Vaults/extendedInformation/write`
  - `Microsoft.RecoveryServices/Vaults/monitoringAlerts/read`
  - `Microsoft.RecoveryServices/Vaults/monitoringConfigurations/*`
  - `Microsoft.RecoveryServices/Vaults/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/write`
  - `Microsoft.RecoveryServices/Vaults/usages/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/storageAccounts/read`
  - `Microsoft.RecoveryServices/Vaults/backupstorageconfig/*`
  - `Microsoft.RecoveryServices/Vaults/backupValidateOperation/action`
  - `Microsoft.RecoveryServices/Vaults/backupTriggerValidateOperation/action`
  - `Microsoft.RecoveryServices/Vaults/backupValidateOperationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupValidateOperationsStatuses/read`
  - `Microsoft.RecoveryServices/Vaults/backupOperations/read`
  - `Microsoft.RecoveryServices/Vaults/backupPolicies/operations/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/write`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/inquire/action`
  - `Microsoft.RecoveryServices/Vaults/backupEngines/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/backupProtectionIntent/write`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/backupProtectionIntent/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectableContainers/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/items/read`
  - `Microsoft.RecoveryServices/locations/backupStatus/action`
  - `Microsoft.RecoveryServices/locations/backupPreValidateProtection/action`
  - `Microsoft.RecoveryServices/locations/backupValidateFeatures/action`
  - `Microsoft.RecoveryServices/locations/backupAadProperties/read`
  - `Microsoft.RecoveryServices/locations/backupCrrJobs/action`
  - `Microsoft.RecoveryServices/locations/backupCrrJob/action`
  - `Microsoft.RecoveryServices/locations/backupCrossRegionRestore/action`
  - `Microsoft.RecoveryServices/locations/backupCrrOperationResults/read`
  - `Microsoft.RecoveryServices/locations/backupCrrOperationsStatus/read`
  - `Microsoft.RecoveryServices/Vaults/monitoringAlerts/write`
  - `Microsoft.RecoveryServices/operations/read`
  - `Microsoft.RecoveryServices/locations/operationStatus/read`
  - `Microsoft.RecoveryServices/Vaults/backupProtectionIntents/read`
  - `Microsoft.Support/*`
  - `Microsoft.DataProtection/backupVaults/backupInstances/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/read`
  - `Microsoft.DataProtection/backupVaults/backupPolicies/read`
  - `Microsoft.DataProtection/backupVaults/backupPolicies/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/recoveryPoints/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/recoveryPoints/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/findRestorableTimeRanges/action`
  - `Microsoft.DataProtection/backupVaults/read`
  - `Microsoft.DataProtection/backupVaults/operationResults/read`
  - `Microsoft.DataProtection/backupVaults/read`
  - `Microsoft.DataProtection/backupVaults/read`
  - `Microsoft.DataProtection/locations/operationStatus/read`
  - `Microsoft.DataProtection/locations/operationResults/read`
  - `Microsoft.DataProtection/providers/operations/read`


---

#### `Backup Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.RecoveryServices/locations/allocatedStamp/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/operationsStatus/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/read`
  - `Microsoft.RecoveryServices/Vaults/backupJobs/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupJobs/read`
  - `Microsoft.RecoveryServices/Vaults/backupJobsExport/action`
  - `Microsoft.RecoveryServices/Vaults/backupOperationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupPolicies/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/backupPolicies/read`
  - `Microsoft.RecoveryServices/Vaults/backupProtectedItems/read`
  - `Microsoft.RecoveryServices/Vaults/backupProtectionContainers/read`
  - `Microsoft.RecoveryServices/Vaults/backupUsageSummaries/read`
  - `Microsoft.RecoveryServices/Vaults/extendedInformation/read`
  - `Microsoft.RecoveryServices/Vaults/monitoringAlerts/read`
  - `Microsoft.RecoveryServices/Vaults/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/read`
  - `Microsoft.RecoveryServices/Vaults/backupstorageconfig/read`
  - `Microsoft.RecoveryServices/Vaults/backupconfig/read`
  - `Microsoft.RecoveryServices/Vaults/backupOperations/read`
  - `Microsoft.RecoveryServices/Vaults/backupPolicies/operations/read`
  - `Microsoft.RecoveryServices/Vaults/backupEngines/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/backupProtectionIntent/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/items/read`
  - `Microsoft.RecoveryServices/locations/backupStatus/action`
  - `Microsoft.RecoveryServices/Vaults/monitoringConfigurations/*`
  - `Microsoft.RecoveryServices/Vaults/monitoringAlerts/write`
  - `Microsoft.RecoveryServices/operations/read`
  - `Microsoft.RecoveryServices/locations/operationStatus/read`
  - `Microsoft.RecoveryServices/Vaults/backupProtectionIntents/read`
  - `Microsoft.RecoveryServices/Vaults/usages/read`
  - `Microsoft.RecoveryServices/locations/backupValidateFeatures/action`
  - `Microsoft.RecoveryServices/locations/backupCrrJobs/action`
  - `Microsoft.RecoveryServices/locations/backupCrrJob/action`
  - `Microsoft.RecoveryServices/locations/backupCrrOperationResults/read`
  - `Microsoft.RecoveryServices/locations/backupCrrOperationsStatus/read`
  - `Microsoft.DataProtection/locations/getBackupStatus/action`
  - `Microsoft.DataProtection/backupVaults/backupInstances/write`
  - `Microsoft.DataProtection/backupVaults/backupInstances/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/backup/action`
  - `Microsoft.DataProtection/backupVaults/backupInstances/validateRestore/action`
  - `Microsoft.DataProtection/backupVaults/backupInstances/restore/action`
  - `Microsoft.DataProtection/backupVaults/backupPolicies/read`
  - `Microsoft.DataProtection/backupVaults/backupPolicies/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/recoveryPoints/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/recoveryPoints/read`
  - `Microsoft.DataProtection/backupVaults/backupInstances/findRestorableTimeRanges/action`
  - `Microsoft.DataProtection/backupVaults/read`
  - `Microsoft.DataProtection/backupVaults/operationResults/read`
  - `Microsoft.DataProtection/backupVaults/read`
  - `Microsoft.DataProtection/backupVaults/read`
  - `Microsoft.DataProtection/locations/operationStatus/read`
  - `Microsoft.DataProtection/locations/operationResults/read`
  - `Microsoft.DataProtection/backupVaults/validateForBackup/action`
  - `Microsoft.DataProtection/providers/operations/read`


---

#### `Billing Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Billing/*/read`
  - `Microsoft.Commerce/*/read`
  - `Microsoft.Consumption/*/read`
  - `Microsoft.Management/managementGroups/read`
  - `Microsoft.CostManagement/*/read`
  - `Microsoft.Support/*`


---

#### `BizTalk Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.BizTalkServices/BizTalk/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Blockchain Member Node Access (Preview)`


- Actions:
  - `Microsoft.Blockchain/blockchainMembers/transactionNodes/read`

- DataActions:
  - `Microsoft.Blockchain/blockchainMembers/transactionNodes/connect/action`


---

#### `Blueprint Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Blueprint/blueprints/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Support/*`


---

#### `Blueprint Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Blueprint/blueprintAssignments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Support/*`


---

#### `CDN Endpoint Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Cdn/edgenodes/read`
  - `Microsoft.Cdn/operationresults/*`
  - `Microsoft.Cdn/profiles/endpoints/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `CDN Endpoint Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Cdn/edgenodes/read`
  - `Microsoft.Cdn/operationresults/*`
  - `Microsoft.Cdn/profiles/endpoints/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `CDN Profile Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Cdn/edgenodes/read`
  - `Microsoft.Cdn/operationresults/*`
  - `Microsoft.Cdn/profiles/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `CDN Profile Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Cdn/edgenodes/read`
  - `Microsoft.Cdn/operationresults/*`
  - `Microsoft.Cdn/profiles/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Chamber Admin`


- Actions:
  - `Microsoft.HpcWorkbench/*/read`
  - `Microsoft.HpcWorkbench/instances/chambers/*`
  - `Microsoft.HpcWorkbench/instances/consortiums/*/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`


---

#### `Chamber User`


- Actions:
  - `Microsoft.HpcWorkbench/instances/chambers/*/read`
  - `Microsoft.HpcWorkbench/instances/consortiums/*/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`


---

#### `Classic Network Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.ClassicNetwork/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Classic Storage Account Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.ClassicStorage/storageAccounts/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Classic Storage Account Key Operator Service Role`


- Actions:
  - `Microsoft.ClassicStorage/storageAccounts/listkeys/action`
  - `Microsoft.ClassicStorage/storageAccounts/regeneratekey/action`


---

#### `Classic Virtual Machine Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.ClassicCompute/domainNames/*`
  - `Microsoft.ClassicCompute/virtualMachines/*`
  - `Microsoft.ClassicNetwork/networkSecurityGroups/join/action`
  - `Microsoft.ClassicNetwork/reservedIps/link/action`
  - `Microsoft.ClassicNetwork/reservedIps/read`
  - `Microsoft.ClassicNetwork/virtualNetworks/join/action`
  - `Microsoft.ClassicNetwork/virtualNetworks/read`
  - `Microsoft.ClassicStorage/storageAccounts/disks/read`
  - `Microsoft.ClassicStorage/storageAccounts/images/read`
  - `Microsoft.ClassicStorage/storageAccounts/listKeys/action`
  - `Microsoft.ClassicStorage/storageAccounts/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `ClearDB MySQL DB Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `successbricks.cleardb/databases/*`


---

#### `CodeSigning Certificate Profile Signer`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`

- DataActions:
  - `Microsoft.CodeSigning/certificateProfiles/Sign/action`


---

#### `Cognitive Services Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.CognitiveServices/*`
  - `Microsoft.Features/features/read`
  - `Microsoft.Features/providers/features/read`
  - `Microsoft.Features/providers/features/register/action`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/diagnosticSettings/*`
  - `Microsoft.Insights/logDefinitions/read`
  - `Microsoft.Insights/metricdefinitions/read`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/deployments/operations/read`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Cognitive Services Custom Vision Contributor`


- Actions:
  - `Microsoft.CognitiveServices/*/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVision/*`


---

#### `Cognitive Services Custom Vision Deployment`


- Actions:
  - `Microsoft.CognitiveServices/*/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVision/*/read`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/predictions/*`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/iterations/publish/*`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/iterations/export/*`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/quicktest/*`
  - `Microsoft.CognitiveServices/accounts/CustomVision/classify/*`
  - `Microsoft.CognitiveServices/accounts/CustomVision/detect/*`

- NotDataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/export/read`


---

#### `Cognitive Services Custom Vision Labeler`


- Actions:
  - `Microsoft.CognitiveServices/*/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVision/*/read`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/predictions/query/action`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/images/*`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/tags/*`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/images/suggested/*`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/tagsandregions/suggestions/action`

- NotDataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/export/read`


---

#### `Cognitive Services Custom Vision Reader`


- Actions:
  - `Microsoft.CognitiveServices/*/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVision/*/read`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/predictions/query/action`

- NotDataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/export/read`


---

#### `Cognitive Services Custom Vision Trainer`


- Actions:
  - `Microsoft.CognitiveServices/*/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVision/*`

- NotDataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/action`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/delete`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/import/action`
  - `Microsoft.CognitiveServices/accounts/CustomVision/projects/export/read`


---

#### `Cognitive Services Data Reader (Preview)`


- DataActions:
  - `Microsoft.CognitiveServices/*/read`


---

#### `Cognitive Services Face Recognizer`


- DataActions:
  - `Microsoft.CognitiveServices/accounts/Face/detect/action`
  - `Microsoft.CognitiveServices/accounts/Face/verify/action`
  - `Microsoft.CognitiveServices/accounts/Face/identify/action`
  - `Microsoft.CognitiveServices/accounts/Face/group/action`
  - `Microsoft.CognitiveServices/accounts/Face/findsimilars/action`


---

#### `Cognitive Services Immersive Reader User`


- DataActions:
  - `Microsoft.CognitiveServices/accounts/ImmersiveReader/getcontentmodelforreader/action`


---

#### `Cognitive Services Language Owner`


- Actions:
  - `Microsoft.CognitiveServices/*/read`
  - `Microsoft.CognitiveServices/accounts/listkeys/action`
  - `Microsoft.Authorization/roleAssignments/read`
  - `Microsoft.Authorization/roleDefinitions/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/LanguageAuthoring/*`
  - `Microsoft.CognitiveServices/accounts/ConversationalLanguageUnderstanding/*`


---

#### `Cognitive Services Language Reader`


- Actions:
  - `Microsoft.CognitiveServices/*/read`
  - `Microsoft.Authorization/roleAssignments/read`
  - `Microsoft.Authorization/roleDefinitions/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/LanguageAuthoring/*/read`
  - `Microsoft.CognitiveServices/accounts/ConversationalLanguageUnderstanding/*/read`
  - `Microsoft.CognitiveServices/accounts/ConversationalLanguageUnderstanding/projects/export/action`


---

#### `Cognitive Services Language Writer`


- Actions:
  - `Microsoft.CognitiveServices/*/read`
  - `Microsoft.Authorization/roleAssignments/read`
  - `Microsoft.Authorization/roleDefinitions/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/LanguageAuthoring/*`
  - `Microsoft.CognitiveServices/accounts/ConversationalLanguageUnderstanding/*`

- NotDataActions:
  - `Microsoft.CognitiveServices/accounts/LanguageAuthoring/projects/publish/action`
  - `Microsoft.CognitiveServices/accounts/ConversationalLanguageUnderstanding/projects/deployments/write`


---

#### `Cognitive Services LUIS Owner`


- Actions:
  - `Microsoft.CognitiveServices/*/read`
  - `Microsoft.CognitiveServices/accounts/listkeys/action`
  - `Microsoft.Authorization/roleAssignments/read`
  - `Microsoft.Authorization/roleDefinitions/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/LUIS/*`


---

#### `Cognitive Services LUIS Reader`


- Actions:
  - `Microsoft.CognitiveServices/*/read`
  - `Microsoft.Authorization/roleAssignments/read`
  - `Microsoft.Authorization/roleDefinitions/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/LUIS/*/read`
  - `Microsoft.CognitiveServices/accounts/LUIS/apps/testdatasets/write`


---

#### `Cognitive Services LUIS Writer`


- Actions:
  - `Microsoft.CognitiveServices/*/read`
  - `Microsoft.Authorization/roleAssignments/read`
  - `Microsoft.Authorization/roleDefinitions/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/LUIS/*`

- NotDataActions:
  - `Microsoft.CognitiveServices/accounts/LUIS/apps/delete`
  - `Microsoft.CognitiveServices/accounts/LUIS/apps/move/action`
  - `Microsoft.CognitiveServices/accounts/LUIS/apps/publish/action`
  - `Microsoft.CognitiveServices/accounts/LUIS/apps/settings/write`
  - `Microsoft.CognitiveServices/accounts/LUIS/apps/azureaccounts/action`
  - `Microsoft.CognitiveServices/accounts/LUIS/apps/azureaccounts/delete`


---

#### `Cognitive Services Metrics Advisor Administrator`


- Actions:
  - `Microsoft.CognitiveServices/*/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/MetricsAdvisor/*`


---

#### `Cognitive Services Metrics Advisor User`


- Actions:
  - `Microsoft.CognitiveServices/*/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/MetricsAdvisor/*`

- NotDataActions:
  - `Microsoft.CognitiveServices/accounts/MetricsAdvisor/stats/*`


---

#### `Cognitive Services QnA Maker Editor`


- Actions:
  - `Microsoft.CognitiveServices/*/read`
  - `Microsoft.Authorization/roleAssignments/read`
  - `Microsoft.Authorization/roleDefinitions/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/QnAMaker/knowledgebases/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/knowledgebases/download/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/knowledgebases/create/write`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/knowledgebases/write`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/knowledgebases/generateanswer/action`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/knowledgebases/train/action`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/alterations/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/alterations/write`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/endpointkeys/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/endpointkeys/refreshkeys/action`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/endpointsettings/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/endpointsettings/write`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/operations/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/knowledgebases/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/knowledgebases/download/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/knowledgebases/create/write`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/knowledgebases/write`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/knowledgebases/generateanswer/action`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/knowledgebases/train/action`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/alterations/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/alterations/write`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/endpointkeys/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/endpointkeys/refreshkeys/action`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/endpointsettings/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/endpointsettings/write`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/operations/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/knowledgebases/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/knowledgebases/download/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/knowledgebases/create/write`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/knowledgebases/write`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/knowledgebases/generateanswer/action`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/knowledgebases/train/action`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/alterations/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/alterations/write`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/endpointkeys/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/endpointkeys/refreshkeys/action`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/endpointsettings/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/endpointsettings/write`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/operations/read`


---

#### `Cognitive Services QnA Maker Reader`


- Actions:
  - `Microsoft.CognitiveServices/*/read`
  - `Microsoft.Authorization/roleAssignments/read`
  - `Microsoft.Authorization/roleDefinitions/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/QnAMaker/knowledgebases/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/knowledgebases/download/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/knowledgebases/generateanswer/action`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/alterations/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/endpointkeys/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker/endpointsettings/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/knowledgebases/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/knowledgebases/download/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/knowledgebases/generateanswer/action`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/alterations/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/endpointkeys/read`
  - `Microsoft.CognitiveServices/accounts/QnAMaker.v2/endpointsettings/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/knowledgebases/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/knowledgebases/download/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/knowledgebases/generateanswer/action`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/alterations/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/endpointkeys/read`
  - `Microsoft.CognitiveServices/accounts/TextAnalytics/QnAMaker/endpointsettings/read`


---

#### `Cognitive Services Speech Contributor`


- Actions:
  - `Microsoft.CognitiveServices/*/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/SpeechServices/*`
  - `Microsoft.CognitiveServices/accounts/CustomVoice/*`


---

#### `Cognitive Services Speech User`


- Actions:
  - `Microsoft.CognitiveServices/*/read`

- DataActions:
  - `Microsoft.CognitiveServices/accounts/SpeechServices/*/read`
  - `Microsoft.CognitiveServices/accounts/SpeechServices/*/transcriptions/write`
  - `Microsoft.CognitiveServices/accounts/SpeechServices/*/transcriptions/delete`
  - `Microsoft.CognitiveServices/accounts/SpeechServices/*/transcriptions/read`
  - `Microsoft.CognitiveServices/accounts/SpeechServices/*/frontend/action`
  - `Microsoft.CognitiveServices/accounts/SpeechServices/text-dependent/*/action`
  - `Microsoft.CognitiveServices/accounts/SpeechServices/text-independent/*/action`
  - `Microsoft.CognitiveServices/accounts/CustomVoice/*/read`
  - `Microsoft.CognitiveServices/accounts/CustomVoice/evaluations/*`
  - `Microsoft.CognitiveServices/accounts/CustomVoice/longaudiosynthesis/*`

- NotDataActions:
  - `Microsoft.CognitiveServices/accounts/CustomVoice/trainingsets/files/read`
  - `Microsoft.CognitiveServices/accounts/CustomVoice/datasets/files/read`
  - `Microsoft.CognitiveServices/accounts/CustomVoice/trainingsets/utterances/read`


---

#### `Cognitive Services User`


- Actions:
  - `Microsoft.CognitiveServices/*/read`
  - `Microsoft.CognitiveServices/accounts/listkeys/action`
  - `Microsoft.Insights/alertRules/read`
  - `Microsoft.Insights/diagnosticSettings/read`
  - `Microsoft.Insights/logDefinitions/read`
  - `Microsoft.Insights/metricdefinitions/read`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/operations/read`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- DataActions:
  - `Microsoft.CognitiveServices/*`


---

#### `Collaborative Data Contributor`


- Actions:
  - `Microsoft.IndustryDataLifecycle/custodianCollaboratives/*/read`
  - `Microsoft.IndustryDataLifecycle/memberCollaboratives/*/read`
  - `Microsoft.IndustryDataLifecycle/locations/dataPackages/*`
  - `Microsoft.IndustryDataLifecycle/custodianCollaboratives/receivedDataPackages/*`
  - `Microsoft.IndustryDataLifecycle/custodianCollaboratives/rejectDataPackage/action`
  - `Microsoft.IndustryDataLifecycle/memberCollaboratives/sharedDataPackages/*`
  - `Microsoft.IndustryDataLifecycle/custodianCollaboratives/dataModels/*`
  - `Microsoft.IndustryDataLifecycle/custodianCollaboratives/auditLogs/action`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Collaborative Runtime Operator`


- Actions:
  - `Microsoft.IndustryDataLifecycle/derivedModels/*`
  - `Microsoft.IndustryDataLifecycle/pipelineSets/*`
  - `Microsoft.IndustryDataLifecycle/modelMappings/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Contributor`


- Actions:
  - `*`

- NotActions:
  - `Microsoft.Authorization/*/Delete`
  - `Microsoft.Authorization/*/Write`
  - `Microsoft.Authorization/elevateAccess/Action`
  - `Microsoft.Blueprint/blueprintAssignments/write`
  - `Microsoft.Blueprint/blueprintAssignments/delete`
  - `Microsoft.Compute/galleries/share/action`


---

#### `Cosmos DB Account Reader Role`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.DocumentDB/*/read`
  - `Microsoft.DocumentDB/databaseAccounts/readonlykeys/action`
  - `Microsoft.Insights/MetricDefinitions/read`
  - `Microsoft.Insights/Metrics/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Cosmos DB Operator`


- Actions:
  - `Microsoft.DocumentDb/databaseAccounts/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action`

- NotActions:
  - `Microsoft.DocumentDB/databaseAccounts/readonlyKeys/*`
  - `Microsoft.DocumentDB/databaseAccounts/regenerateKey/*`
  - `Microsoft.DocumentDB/databaseAccounts/listKeys/*`
  - `Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/*`
  - `Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/write`
  - `Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/delete`
  - `Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write`
  - `Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/delete`


---

#### `CosmosBackupOperator`


- Actions:
  - `Microsoft.DocumentDB/databaseAccounts/backup/action`
  - `Microsoft.DocumentDB/databaseAccounts/restore/action`


---

#### `CosmosRestoreOperator`


- Actions:
  - `Microsoft.DocumentDB/locations/restorableDatabaseAccounts/restore/action`
  - `Microsoft.DocumentDB/locations/restorableDatabaseAccounts/*/read`
  - `Microsoft.DocumentDB/locations/restorableDatabaseAccounts/read`


---

#### `Cost Management Contributor`


- Actions:
  - `Microsoft.Consumption/*`
  - `Microsoft.CostManagement/*`
  - `Microsoft.Billing/billingPeriods/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Advisor/configurations/read`
  - `Microsoft.Advisor/recommendations/read`
  - `Microsoft.Management/managementGroups/read`
  - `Microsoft.Billing/billingProperty/read`


---

#### `Cost Management Reader`


- Actions:
  - `Microsoft.Consumption/*/read`
  - `Microsoft.CostManagement/*/read`
  - `Microsoft.Billing/billingPeriods/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Advisor/configurations/read`
  - `Microsoft.Advisor/recommendations/read`
  - `Microsoft.Management/managementGroups/read`
  - `Microsoft.Billing/billingProperty/read`


---

#### `Data Box Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Databox/*`


---

#### `Data Box Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Databox/*/read`
  - `Microsoft.Databox/jobs/listsecrets/action`
  - `Microsoft.Databox/jobs/listcredentials/action`
  - `Microsoft.Databox/locations/availableSkus/action`
  - `Microsoft.Databox/locations/validateInputs/action`
  - `Microsoft.Databox/locations/regionConfiguration/action`
  - `Microsoft.Databox/locations/validateAddress/action`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Support/*`


---

#### `Data Factory Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.DataFactory/dataFactories/*`
  - `Microsoft.DataFactory/factories/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.EventGrid/eventSubscriptions/write`


---

#### `Data Lake Analytics Developer`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.BigAnalytics/accounts/*`
  - `Microsoft.DataLakeAnalytics/accounts/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- NotActions:
  - `Microsoft.BigAnalytics/accounts/Delete`
  - `Microsoft.BigAnalytics/accounts/TakeOwnership/action`
  - `Microsoft.BigAnalytics/accounts/Write`
  - `Microsoft.DataLakeAnalytics/accounts/Delete`
  - `Microsoft.DataLakeAnalytics/accounts/TakeOwnership/action`
  - `Microsoft.DataLakeAnalytics/accounts/Write`
  - `Microsoft.DataLakeAnalytics/accounts/dataLakeStoreAccounts/Write`
  - `Microsoft.DataLakeAnalytics/accounts/dataLakeStoreAccounts/Delete`
  - `Microsoft.DataLakeAnalytics/accounts/storageAccounts/Write`
  - `Microsoft.DataLakeAnalytics/accounts/storageAccounts/Delete`
  - `Microsoft.DataLakeAnalytics/accounts/firewallRules/Write`
  - `Microsoft.DataLakeAnalytics/accounts/firewallRules/Delete`
  - `Microsoft.DataLakeAnalytics/accounts/computePolicies/Write`
  - `Microsoft.DataLakeAnalytics/accounts/computePolicies/Delete`


---

#### `Data Purger`


- Actions:
  - `Microsoft.Insights/components/*/read`
  - `Microsoft.Insights/components/purge/action`
  - `Microsoft.OperationalInsights/workspaces/*/read`
  - `Microsoft.OperationalInsights/workspaces/purge/action`


---

#### `Desktop Virtualization Application Group Contributor`


- Actions:
  - `Microsoft.DesktopVirtualization/applicationgroups/*`
  - `Microsoft.DesktopVirtualization/hostpools/read`
  - `Microsoft.DesktopVirtualization/hostpools/sessionhosts/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Support/*`


---

#### `Desktop Virtualization Application Group Reader`


- Actions:
  - `Microsoft.DesktopVirtualization/applicationgroups/*/read`
  - `Microsoft.DesktopVirtualization/applicationgroups/read`
  - `Microsoft.DesktopVirtualization/hostpools/read`
  - `Microsoft.DesktopVirtualization/hostpools/sessionhosts/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/read`
  - `Microsoft.Support/*`


---

#### `Desktop Virtualization Contributor`


- Actions:
  - `Microsoft.DesktopVirtualization/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Support/*`


---

#### `Desktop Virtualization Host Pool Contributor`


- Actions:
  - `Microsoft.DesktopVirtualization/hostpools/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Support/*`


---

#### `Desktop Virtualization Host Pool Reader`


- Actions:
  - `Microsoft.DesktopVirtualization/hostpools/*/read`
  - `Microsoft.DesktopVirtualization/hostpools/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/read`
  - `Microsoft.Support/*`


---

#### `Desktop Virtualization Reader`


- Actions:
  - `Microsoft.DesktopVirtualization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/read`
  - `Microsoft.Support/*`


---

#### `Desktop Virtualization Session Host Operator`


- Actions:
  - `Microsoft.DesktopVirtualization/hostpools/read`
  - `Microsoft.DesktopVirtualization/hostpools/sessionhosts/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Support/*`


---

#### `Desktop Virtualization User`


- DataActions:
  - `Microsoft.DesktopVirtualization/applicationGroups/useApplications/action`


---

#### `Desktop Virtualization User Session Operator`


- Actions:
  - `Microsoft.DesktopVirtualization/hostpools/read`
  - `Microsoft.DesktopVirtualization/hostpools/sessionhosts/read`
  - `Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Support/*`


---

#### `Desktop Virtualization Workspace Contributor`


- Actions:
  - `Microsoft.DesktopVirtualization/workspaces/*`
  - `Microsoft.DesktopVirtualization/applicationgroups/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Support/*`


---

#### `Desktop Virtualization Workspace Reader`


- Actions:
  - `Microsoft.DesktopVirtualization/workspaces/read`
  - `Microsoft.DesktopVirtualization/applicationgroups/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/read`
  - `Microsoft.Support/*`


---

#### `Device Provisioning Service Data Contributor`


- DataActions:
  - `Microsoft.Devices/provisioningServices/*`


---

#### `Device Provisioning Service Data Reader`


- DataActions:
  - `Microsoft.Devices/provisioningServices/*/read`


---

#### `Device Update Administrator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Insights/alertRules/*`

- DataActions:
  - `Microsoft.DeviceUpdate/accounts/instances/updates/read`
  - `Microsoft.DeviceUpdate/accounts/instances/updates/write`
  - `Microsoft.DeviceUpdate/accounts/instances/updates/delete`
  - `Microsoft.DeviceUpdate/accounts/instances/management/read`
  - `Microsoft.DeviceUpdate/accounts/instances/management/write`
  - `Microsoft.DeviceUpdate/accounts/instances/management/delete`


---

#### `Device Update Content Administrator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Insights/alertRules/*`

- DataActions:
  - `Microsoft.DeviceUpdate/accounts/instances/updates/read`
  - `Microsoft.DeviceUpdate/accounts/instances/updates/write`
  - `Microsoft.DeviceUpdate/accounts/instances/updates/delete`


---

#### `Device Update Content Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Insights/alertRules/*`

- DataActions:
  - `Microsoft.DeviceUpdate/accounts/instances/updates/read`


---

#### `Device Update Deployments Administrator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Insights/alertRules/*`

- DataActions:
  - `Microsoft.DeviceUpdate/accounts/instances/management/read`
  - `Microsoft.DeviceUpdate/accounts/instances/management/write`
  - `Microsoft.DeviceUpdate/accounts/instances/management/delete`
  - `Microsoft.DeviceUpdate/accounts/instances/updates/read`


---

#### `Device Update Deployments Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Insights/alertRules/*`

- DataActions:
  - `Microsoft.DeviceUpdate/accounts/instances/management/read`
  - `Microsoft.DeviceUpdate/accounts/instances/updates/read`


---

#### `Device Update Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Insights/alertRules/*`

- DataActions:
  - `Microsoft.DeviceUpdate/accounts/instances/updates/read`
  - `Microsoft.DeviceUpdate/accounts/instances/management/read`


---

#### `DevTest Labs User`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Compute/availabilitySets/read`
  - `Microsoft.Compute/virtualMachines/*/read`
  - `Microsoft.Compute/virtualMachines/deallocate/action`
  - `Microsoft.Compute/virtualMachines/read`
  - `Microsoft.Compute/virtualMachines/restart/action`
  - `Microsoft.Compute/virtualMachines/start/action`
  - `Microsoft.DevTestLab/*/read`
  - `Microsoft.DevTestLab/labs/claimAnyVm/action`
  - `Microsoft.DevTestLab/labs/createEnvironment/action`
  - `Microsoft.DevTestLab/labs/ensureCurrentUserProfile/action`
  - `Microsoft.DevTestLab/labs/formulas/delete`
  - `Microsoft.DevTestLab/labs/formulas/read`
  - `Microsoft.DevTestLab/labs/formulas/write`
  - `Microsoft.DevTestLab/labs/policySets/evaluatePolicies/action`
  - `Microsoft.DevTestLab/labs/virtualMachines/claim/action`
  - `Microsoft.DevTestLab/labs/virtualmachines/listApplicableSchedules/action`
  - `Microsoft.DevTestLab/labs/virtualMachines/getRdpFileContents/action`
  - `Microsoft.Network/loadBalancers/backendAddressPools/join/action`
  - `Microsoft.Network/loadBalancers/inboundNatRules/join/action`
  - `Microsoft.Network/networkInterfaces/*/read`
  - `Microsoft.Network/networkInterfaces/join/action`
  - `Microsoft.Network/networkInterfaces/read`
  - `Microsoft.Network/networkInterfaces/write`
  - `Microsoft.Network/publicIPAddresses/*/read`
  - `Microsoft.Network/publicIPAddresses/join/action`
  - `Microsoft.Network/publicIPAddresses/read`
  - `Microsoft.Network/virtualNetworks/subnets/join/action`
  - `Microsoft.Resources/deployments/operations/read`
  - `Microsoft.Resources/deployments/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/storageAccounts/listKeys/action`

- NotActions:
  - `Microsoft.Compute/virtualMachines/vmSizes/read`


---

#### `DICOM Data Owner`


- DataActions:
  - `Microsoft.HealthcareApis/workspaces/dicomservices/resources/*`


---

#### `DICOM Data Reader`


- DataActions:
  - `Microsoft.HealthcareApis/workspaces/dicomservices/resources/read`


---

#### `Disk Backup Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Compute/disks/read`
  - `Microsoft.Compute/disks/beginGetAccess/action`


---

#### `Disk Pool Operator`


- Actions:
  - `Microsoft.Compute/disks/write`
  - `Microsoft.Compute/disks/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`


---

#### `Disk Restore Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Compute/disks/write`
  - `Microsoft.Compute/disks/read`


---

#### `Disk Snapshot Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Compute/snapshots/delete`
  - `Microsoft.Compute/snapshots/write`
  - `Microsoft.Compute/snapshots/read`
  - `Microsoft.Compute/snapshots/beginGetAccess/action`
  - `Microsoft.Compute/snapshots/endGetAccess/action`
  - `Microsoft.Compute/disks/beginGetAccess/action`
  - `Microsoft.Storage/storageAccounts/listkeys/action`
  - `Microsoft.Storage/storageAccounts/write`
  - `Microsoft.Storage/storageAccounts/read`
  - `Microsoft.Storage/storageAccounts/delete`


---

#### `DNS Zone Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Network/dnsZones/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `DocumentDB Account Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.DocumentDb/databaseAccounts/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action`


---

#### `EventGrid Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.EventGrid/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `EventGrid Data Sender`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.EventGrid/topics/read`
  - `Microsoft.EventGrid/domains/read`
  - `Microsoft.EventGrid/partnerNamespaces/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`

- DataActions:
  - `Microsoft.EventGrid/events/send/action`


---

#### `EventGrid EventSubscription Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.EventGrid/eventSubscriptions/*`
  - `Microsoft.EventGrid/topicTypes/eventSubscriptions/read`
  - `Microsoft.EventGrid/locations/eventSubscriptions/read`
  - `Microsoft.EventGrid/locations/topicTypes/eventSubscriptions/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `EventGrid EventSubscription Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.EventGrid/eventSubscriptions/read`
  - `Microsoft.EventGrid/topicTypes/eventSubscriptions/read`
  - `Microsoft.EventGrid/locations/eventSubscriptions/read`
  - `Microsoft.EventGrid/locations/topicTypes/eventSubscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`


---

#### `Experimentation Administrator`


- Actions:
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Experimentation/experimentWorkspaces/read`

- DataActions:
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/admin/action`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/read`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/write`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/delete`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/experimentadmin/action`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/experiment/action`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/emergencystop/action`
  - `Microsoft.Experimentation/experimentWorkspaces/read`
  - `Microsoft.Experimentation/experimentWorkspaces/write`
  - `Microsoft.Experimentation/experimentWorkspaces/delete`
  - `Microsoft.Experimentation/experimentWorkspaces/admin/action`
  - `Microsoft.Experimentation/experimentWorkspaces/metricwrite/action`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/metricwrite/action`


---

#### `Experimentation Contributor`


- Actions:
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Experimentation/experimentWorkspaces/read`

- DataActions:
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/read`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/write`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/delete`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/experiment/action`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/emergencystop/action`
  - `Microsoft.Experimentation/experimentWorkspaces/read`
  - `Microsoft.Experimentation/experimentWorkspaces/write`
  - `Microsoft.Experimentation/experimentWorkspaces/delete`


---

#### `Experimentation Metric Contributor`


- Actions:
  - `Microsoft.Experimentation/experimentWorkspaces/read`

- DataActions:
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/read`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/metricwrite/action`
  - `Microsoft.Experimentation/experimentWorkspaces/metricwrite/action`
  - `Microsoft.Experimentation/experimentWorkspaces/read`


---

#### `Experimentation Reader`


- Actions:
  - `Microsoft.Experimentation/experimentWorkspaces/read`

- DataActions:
  - `Microsoft.Experimentation/experimentWorkspaces/read`
  - `Microsoft.Experimentation/experimentWorkspaces/experimentationGroups/read`


---

#### `FHIR Data Contributor`


- DataActions:
  - `Microsoft.HealthcareApis/services/fhir/resources/*`
  - `Microsoft.HealthcareApis/workspaces/fhirservices/resources/*`


---

#### `FHIR Data Converter`


- DataActions:
  - `Microsoft.HealthcareApis/services/fhir/resources/convertData/action`
  - `Microsoft.HealthcareApis/workspaces/fhirservices/resources/convertData/action`


---

#### `FHIR Data Exporter`


- DataActions:
  - `Microsoft.HealthcareApis/services/fhir/resources/read`
  - `Microsoft.HealthcareApis/services/fhir/resources/export/action`
  - `Microsoft.HealthcareApis/workspaces/fhirservices/resources/read`
  - `Microsoft.HealthcareApis/workspaces/fhirservices/resources/export/action`


---

#### `FHIR Data Reader`


- DataActions:
  - `Microsoft.HealthcareApis/services/fhir/resources/read`
  - `Microsoft.HealthcareApis/workspaces/fhirservices/resources/read`


---

#### `FHIR Data Writer`


- DataActions:
  - `Microsoft.HealthcareApis/services/fhir/resources/*`
  - `Microsoft.HealthcareApis/workspaces/fhirservices/resources/*`

- NotDataActions:
  - `Microsoft.HealthcareApis/services/fhir/resources/hardDelete/action`
  - `Microsoft.HealthcareApis/workspaces/fhirservices/resources/hardDelete/action`


---

#### `Grafana Admin`


- DataActions:
  - `Microsoft.Dashboard/grafana/ActAsGrafanaAdmin/action`


---

#### `Grafana Editor`


- DataActions:
  - `Microsoft.Dashboard/grafana/ActAsGrafanaEditor/action`


---

#### `Grafana Viewer`


- DataActions:
  - `Microsoft.Dashboard/grafana/ActAsGrafanaViewer/action`


---

#### `Graph Owner`


- Actions:
  - `Microsoft.EnterpriseKnowledgeGraph/services/conflation/read`
  - `Microsoft.EnterpriseKnowledgeGraph/services/conflation/write`
  - `Microsoft.EnterpriseKnowledgeGraph/services/sourceschema/read`
  - `Microsoft.EnterpriseKnowledgeGraph/services/sourceschema/write`
  - `Microsoft.EnterpriseKnowledgeGraph/services/knowledge/read`
  - `Microsoft.EnterpriseKnowledgeGraph/services/knowledge/write`
  - `Microsoft.EnterpriseKnowledgeGraph/services/intentclassification/read`
  - `Microsoft.EnterpriseKnowledgeGraph/services/intentclassification/write`
  - `Microsoft.EnterpriseKnowledgeGraph/services/ingestion/read`
  - `Microsoft.EnterpriseKnowledgeGraph/services/ingestion/write`
  - `Microsoft.EnterpriseKnowledgeGraph/services/ontology/read`
  - `Microsoft.EnterpriseKnowledgeGraph/services/ontology/write`
  - `Microsoft.EnterpriseKnowledgeGraph/services/delete`
  - `Microsoft.EnterpriseKnowledgeGraph/operations/read`


---

#### `Guest Configuration Resource Contributor`


- Actions:
  - `Microsoft.GuestConfiguration/guestConfigurationAssignments/write`
  - `Microsoft.GuestConfiguration/guestConfigurationAssignments/read`
  - `Microsoft.GuestConfiguration/guestConfigurationAssignments/*/read`


---

#### `HDInsight Cluster Operator`


- Actions:
  - `Microsoft.HDInsight/*/read`
  - `Microsoft.HDInsight/clusters/getGatewaySettings/action`
  - `Microsoft.HDInsight/clusters/updateGatewaySettings/action`
  - `Microsoft.HDInsight/clusters/configurations/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/operations/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Support/*`


---

#### `HDInsight Domain Services Contributor`


- Actions:
  - `Microsoft.AAD/*/read`
  - `Microsoft.AAD/domainServices/*/read`
  - `Microsoft.AAD/domainServices/oucontainer/*`


---

#### `Hierarchy Settings Administrator`


- Actions:
  - `Microsoft.Management/managementGroups/settings/write`
  - `Microsoft.Management/managementGroups/settings/delete`


---

#### `Hybrid Server Onboarding`


- Actions:
  - `Microsoft.HybridCompute/machines/read`
  - `Microsoft.HybridCompute/machines/write`


---

#### `Hybrid Server Resource Administrator`


- Actions:
  - `Microsoft.HybridCompute/machines/*`
  - `Microsoft.HybridCompute/*/read`


---

#### `Integration Service Environment Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Support/*`
  - `Microsoft.Logic/integrationServiceEnvironments/*`


---

#### `Integration Service Environment Developer`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Support/*`
  - `Microsoft.Logic/integrationServiceEnvironments/read`
  - `Microsoft.Logic/integrationServiceEnvironments/*/join/action`


---

#### `Intelligent Systems Account Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.IntelligentSystems/accounts/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `IoT Hub Data Contributor`


- DataActions:
  - `Microsoft.Devices/IotHubs/*`


---

#### `IoT Hub Data Reader`


- DataActions:
  - `Microsoft.Devices/IotHubs/*/read`
  - `Microsoft.Devices/IotHubs/fileUpload/notifications/action`


---

#### `IoT Hub Registry Contributor`


- DataActions:
  - `Microsoft.Devices/IotHubs/devices/*`


---

#### `IoT Hub Twin Contributor`


- DataActions:
  - `Microsoft.Devices/IotHubs/twins/*`


---

#### `Key Vault Administrator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.KeyVault/checkNameAvailability/read`
  - `Microsoft.KeyVault/deletedVaults/read`
  - `Microsoft.KeyVault/locations/*/read`
  - `Microsoft.KeyVault/vaults/*/read`
  - `Microsoft.KeyVault/operations/read`

- DataActions:
  - `Microsoft.KeyVault/vaults/*`


---

#### `Key Vault Certificates Officer`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.KeyVault/checkNameAvailability/read`
  - `Microsoft.KeyVault/deletedVaults/read`
  - `Microsoft.KeyVault/locations/*/read`
  - `Microsoft.KeyVault/vaults/*/read`
  - `Microsoft.KeyVault/operations/read`

- DataActions:
  - `Microsoft.KeyVault/vaults/certificatecas/*`
  - `Microsoft.KeyVault/vaults/certificates/*`


---

#### `Key Vault Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.KeyVault/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- NotActions:
  - `Microsoft.KeyVault/locations/deletedVaults/purge/action`
  - `Microsoft.KeyVault/hsmPools/*`
  - `Microsoft.KeyVault/managedHsms/*`


---

#### `Key Vault Crypto Officer`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.KeyVault/checkNameAvailability/read`
  - `Microsoft.KeyVault/deletedVaults/read`
  - `Microsoft.KeyVault/locations/*/read`
  - `Microsoft.KeyVault/vaults/*/read`
  - `Microsoft.KeyVault/operations/read`

- DataActions:
  - `Microsoft.KeyVault/vaults/keys/*`
  - `Microsoft.KeyVault/vaults/keyrotationpolicies/*`


---

#### `Key Vault Crypto Service Encryption User`


- Actions:
  - `Microsoft.EventGrid/eventSubscriptions/write`
  - `Microsoft.EventGrid/eventSubscriptions/read`
  - `Microsoft.EventGrid/eventSubscriptions/delete`

- DataActions:
  - `Microsoft.KeyVault/vaults/keys/read`
  - `Microsoft.KeyVault/vaults/keys/wrap/action`
  - `Microsoft.KeyVault/vaults/keys/unwrap/action`


---

#### `Key Vault Crypto User`


- DataActions:
  - `Microsoft.KeyVault/vaults/keys/read`
  - `Microsoft.KeyVault/vaults/keys/update/action`
  - `Microsoft.KeyVault/vaults/keys/backup/action`
  - `Microsoft.KeyVault/vaults/keys/encrypt/action`
  - `Microsoft.KeyVault/vaults/keys/decrypt/action`
  - `Microsoft.KeyVault/vaults/keys/wrap/action`
  - `Microsoft.KeyVault/vaults/keys/unwrap/action`
  - `Microsoft.KeyVault/vaults/keys/sign/action`
  - `Microsoft.KeyVault/vaults/keys/verify/action`


---

#### `Key Vault Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.KeyVault/checkNameAvailability/read`
  - `Microsoft.KeyVault/deletedVaults/read`
  - `Microsoft.KeyVault/locations/*/read`
  - `Microsoft.KeyVault/vaults/*/read`
  - `Microsoft.KeyVault/operations/read`

- DataActions:
  - `Microsoft.KeyVault/vaults/*/read`
  - `Microsoft.KeyVault/vaults/secrets/readMetadata/action`


---

#### `Key Vault Secrets Officer`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.KeyVault/checkNameAvailability/read`
  - `Microsoft.KeyVault/deletedVaults/read`
  - `Microsoft.KeyVault/locations/*/read`
  - `Microsoft.KeyVault/vaults/*/read`
  - `Microsoft.KeyVault/operations/read`

- DataActions:
  - `Microsoft.KeyVault/vaults/secrets/*`


---

#### `Key Vault Secrets User`


- DataActions:
  - `Microsoft.KeyVault/vaults/secrets/getSecret/action`
  - `Microsoft.KeyVault/vaults/secrets/readMetadata/action`


---

#### `Knowledge Consumer`


- Actions:
  - `Microsoft.EnterpriseKnowledgeGraph/services/knowledge/read`


---

#### `Kubernetes Cluster - Azure Arc Onboarding`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/write`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Kubernetes/connectedClusters/Write`
  - `Microsoft.Kubernetes/connectedClusters/read`
  - `Microsoft.Support/*`


---

#### `Kubernetes Extension Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.KubernetesConfiguration/extensions/write`
  - `Microsoft.KubernetesConfiguration/extensions/read`
  - `Microsoft.KubernetesConfiguration/extensions/delete`
  - `Microsoft.KubernetesConfiguration/extensions/operations/read`


---

#### `Lab Assistant`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.LabServices/labPlans/images/read`
  - `Microsoft.LabServices/labPlans/read`
  - `Microsoft.LabServices/labs/read`
  - `Microsoft.LabServices/labs/schedules/read`
  - `Microsoft.LabServices/labs/users/read`
  - `Microsoft.LabServices/labs/users/invite/action`
  - `Microsoft.LabServices/labs/virtualMachines/read`
  - `Microsoft.LabServices/labs/virtualMachines/start/action`
  - `Microsoft.LabServices/labs/virtualMachines/stop/action`
  - `Microsoft.LabServices/labs/virtualMachines/reimage/action`
  - `Microsoft.LabServices/labs/virtualMachines/redeploy/action`
  - `Microsoft.LabServices/locations/usages/read`
  - `Microsoft.LabServices/skus/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`


---

#### `Lab Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.LabServices/labPlans/images/read`
  - `Microsoft.LabServices/labPlans/read`
  - `Microsoft.LabServices/labPlans/saveImage/action`
  - `Microsoft.LabServices/labs/read`
  - `Microsoft.LabServices/labs/write`
  - `Microsoft.LabServices/labs/delete`
  - `Microsoft.LabServices/labs/publish/action`
  - `Microsoft.LabServices/labs/syncGroup/action`
  - `Microsoft.LabServices/labs/schedules/read`
  - `Microsoft.LabServices/labs/schedules/write`
  - `Microsoft.LabServices/labs/schedules/delete`
  - `Microsoft.LabServices/labs/users/read`
  - `Microsoft.LabServices/labs/users/write`
  - `Microsoft.LabServices/labs/users/delete`
  - `Microsoft.LabServices/labs/users/invite/action`
  - `Microsoft.LabServices/labs/virtualMachines/read`
  - `Microsoft.LabServices/labs/virtualMachines/start/action`
  - `Microsoft.LabServices/labs/virtualMachines/stop/action`
  - `Microsoft.LabServices/labs/virtualMachines/reimage/action`
  - `Microsoft.LabServices/labs/virtualMachines/redeploy/action`
  - `Microsoft.LabServices/labs/virtualMachines/resetPassword/action`
  - `Microsoft.LabServices/locations/usages/read`
  - `Microsoft.LabServices/skus/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`

- DataActions:
  - `Microsoft.LabServices/labPlans/createLab/action`


---

#### `Lab Creator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.LabServices/labAccounts/*/read`
  - `Microsoft.LabServices/labAccounts/createLab/action`
  - `Microsoft.LabServices/labAccounts/getPricingAndAvailability/action`
  - `Microsoft.LabServices/labAccounts/getRestrictionsAndUsage/action`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.LabServices/labPlans/images/read`
  - `Microsoft.LabServices/labPlans/read`
  - `Microsoft.LabServices/labPlans/saveImage/action`
  - `Microsoft.LabServices/labs/read`
  - `Microsoft.LabServices/labs/schedules/read`
  - `Microsoft.LabServices/labs/users/read`
  - `Microsoft.LabServices/labs/virtualMachines/read`
  - `Microsoft.LabServices/locations/usages/read`
  - `Microsoft.LabServices/skus/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- DataActions:
  - `Microsoft.LabServices/labPlans/createLab/action`


---

#### `Lab Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.LabServices/labPlans/images/read`
  - `Microsoft.LabServices/labPlans/read`
  - `Microsoft.LabServices/labPlans/saveImage/action`
  - `Microsoft.LabServices/labs/publish/action`
  - `Microsoft.LabServices/labs/read`
  - `Microsoft.LabServices/labs/schedules/read`
  - `Microsoft.LabServices/labs/schedules/write`
  - `Microsoft.LabServices/labs/schedules/delete`
  - `Microsoft.LabServices/labs/users/read`
  - `Microsoft.LabServices/labs/users/write`
  - `Microsoft.LabServices/labs/users/delete`
  - `Microsoft.LabServices/labs/users/invite/action`
  - `Microsoft.LabServices/labs/virtualMachines/read`
  - `Microsoft.LabServices/labs/virtualMachines/start/action`
  - `Microsoft.LabServices/labs/virtualMachines/stop/action`
  - `Microsoft.LabServices/labs/virtualMachines/reimage/action`
  - `Microsoft.LabServices/labs/virtualMachines/redeploy/action`
  - `Microsoft.LabServices/labs/virtualMachines/resetPassword/action`
  - `Microsoft.LabServices/locations/usages/read`
  - `Microsoft.LabServices/skus/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`


---

#### `Lab Services Contributor`


- Actions:
  - `Microsoft.LabServices/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`

- DataActions:
  - `Microsoft.LabServices/labPlans/createLab/action`


---

#### `Lab Services Reader`


- Actions:
  - `Microsoft.LabServices/*/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`


---

#### `Load Test Contributor`


- Actions:
  - `Microsoft.LoadTestService/*/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Insights/alertRules/*`

- DataActions:
  - `Microsoft.LoadTestService/loadtests/*`


---

#### `Load Test Owner`


- Actions:
  - `Microsoft.LoadTestService/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Insights/alertRules/*`

- DataActions:
  - `Microsoft.LoadTestService/*`


---

#### `Load Test Reader`


- Actions:
  - `Microsoft.LoadTestService/*/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Insights/alertRules/*`

- DataActions:
  - `Microsoft.LoadTestService/loadtests/readTest/action`


---

#### `Log Analytics Contributor`


- Actions:
  - `*/read`
  - `Microsoft.ClassicCompute/virtualMachines/extensions/*`
  - `Microsoft.ClassicStorage/storageAccounts/listKeys/action`
  - `Microsoft.Compute/virtualMachines/extensions/*`
  - `Microsoft.HybridCompute/machines/extensions/write`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/diagnosticSettings/*`
  - `Microsoft.OperationalInsights/*`
  - `Microsoft.OperationsManagement/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourcegroups/deployments/*`
  - `Microsoft.Storage/storageAccounts/listKeys/action`
  - `Microsoft.Support/*`


---

#### `Log Analytics Reader`


- Actions:
  - `*/read`
  - `Microsoft.OperationalInsights/workspaces/analytics/query/action`
  - `Microsoft.OperationalInsights/workspaces/search/action`
  - `Microsoft.Support/*`

- NotActions:
  - `Microsoft.OperationalInsights/workspaces/sharedKeys/read`


---

#### `Logic App Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.ClassicStorage/storageAccounts/listKeys/action`
  - `Microsoft.ClassicStorage/storageAccounts/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/metricAlerts/*`
  - `Microsoft.Insights/diagnosticSettings/*`
  - `Microsoft.Insights/logdefinitions/*`
  - `Microsoft.Insights/metricDefinitions/*`
  - `Microsoft.Logic/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/storageAccounts/listkeys/action`
  - `Microsoft.Storage/storageAccounts/read`
  - `Microsoft.Support/*`
  - `Microsoft.Web/connectionGateways/*`
  - `Microsoft.Web/connections/*`
  - `Microsoft.Web/customApis/*`
  - `Microsoft.Web/serverFarms/join/action`
  - `Microsoft.Web/serverFarms/read`
  - `Microsoft.Web/sites/functions/listSecrets/action`


---

#### `Logic App Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*/read`
  - `Microsoft.Insights/metricAlerts/*/read`
  - `Microsoft.Insights/diagnosticSettings/*/read`
  - `Microsoft.Insights/metricDefinitions/*/read`
  - `Microsoft.Logic/*/read`
  - `Microsoft.Logic/workflows/disable/action`
  - `Microsoft.Logic/workflows/enable/action`
  - `Microsoft.Logic/workflows/validate/action`
  - `Microsoft.Resources/deployments/operations/read`
  - `Microsoft.Resources/subscriptions/operationresults/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Web/connectionGateways/*/read`
  - `Microsoft.Web/connections/*/read`
  - `Microsoft.Web/customApis/*/read`
  - `Microsoft.Web/serverFarms/read`


---

#### `Managed Application Contributor Role`


- Actions:
  - `*/read`
  - `Microsoft.Solutions/applications/*`
  - `Microsoft.Solutions/register/action`
  - `Microsoft.Resources/subscriptions/resourceGroups/*`
  - `Microsoft.Resources/deployments/*`


---

#### `Managed Application Operator Role`


- Actions:
  - `*/read`
  - `Microsoft.Solutions/applications/read`
  - `Microsoft.Solutions/*/action`


---

#### `Managed Applications Reader`


- Actions:
  - `*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Solutions/jitRequests/*`


---

#### `Managed HSM contributor`


- Actions:
  - `Microsoft.KeyVault/managedHSMs/*`


---

#### `Managed Identity Contributor`


- Actions:
  - `Microsoft.ManagedIdentity/userAssignedIdentities/read`
  - `Microsoft.ManagedIdentity/userAssignedIdentities/write`
  - `Microsoft.ManagedIdentity/userAssignedIdentities/delete`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Support/*`


---

#### `Managed Identity Operator`


- Actions:
  - `Microsoft.ManagedIdentity/userAssignedIdentities/*/read`
  - `Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Support/*`


---

#### `Managed Services Registration assignment Delete Role`


- Actions:
  - `Microsoft.ManagedServices/registrationAssignments/read`
  - `Microsoft.ManagedServices/registrationAssignments/delete`
  - `Microsoft.ManagedServices/operationStatuses/read`


---

#### `Management Group Contributor`


- Actions:
  - `Microsoft.Management/managementGroups/delete`
  - `Microsoft.Management/managementGroups/read`
  - `Microsoft.Management/managementGroups/subscriptions/delete`
  - `Microsoft.Management/managementGroups/subscriptions/write`
  - `Microsoft.Management/managementGroups/write`
  - `Microsoft.Management/managementGroups/subscriptions/read`


---

#### `Management Group Reader`


- Actions:
  - `Microsoft.Management/managementGroups/read`
  - `Microsoft.Management/managementGroups/subscriptions/read`


---

#### `Media Services Account Administrator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.Insights/metricDefinitions/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Media/mediaservices/*/read`
  - `Microsoft.Media/mediaservices/assets/listStreamingLocators/action`
  - `Microsoft.Media/mediaservices/streamingLocators/listPaths/action`
  - `Microsoft.Media/mediaservices/write`
  - `Microsoft.Media/mediaservices/delete`
  - `Microsoft.Media/mediaservices/privateEndpointConnectionsApproval/action`
  - `Microsoft.Media/mediaservices/privateEndpointConnections/*`


---

#### `Media Services Live Events Administrator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.Insights/metricDefinitions/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Media/mediaservices/*/read`
  - `Microsoft.Media/mediaservices/assets/*`
  - `Microsoft.Media/mediaservices/assets/assetfilters/*`
  - `Microsoft.Media/mediaservices/streamingLocators/*`
  - `Microsoft.Media/mediaservices/liveEvents/*`

- NotActions:
  - `Microsoft.Media/mediaservices/assets/getEncryptionKey/action`
  - `Microsoft.Media/mediaservices/streamingLocators/listContentKeys/action`


---

#### `Media Services Media Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.Insights/metricDefinitions/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Media/mediaservices/*/read`
  - `Microsoft.Media/mediaservices/assets/*`
  - `Microsoft.Media/mediaservices/assets/assetfilters/*`
  - `Microsoft.Media/mediaservices/streamingLocators/*`
  - `Microsoft.Media/mediaservices/transforms/jobs/*`

- NotActions:
  - `Microsoft.Media/mediaservices/assets/getEncryptionKey/action`
  - `Microsoft.Media/mediaservices/streamingLocators/listContentKeys/action`


---

#### `Media Services Policy Administrator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.Insights/metricDefinitions/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Media/mediaservices/*/read`
  - `Microsoft.Media/mediaservices/assets/listStreamingLocators/action`
  - `Microsoft.Media/mediaservices/streamingLocators/listPaths/action`
  - `Microsoft.Media/mediaservices/accountFilters/*`
  - `Microsoft.Media/mediaservices/streamingPolicies/*`
  - `Microsoft.Media/mediaservices/contentKeyPolicies/*`
  - `Microsoft.Media/mediaservices/transforms/*`

- NotActions:
  - `Microsoft.Media/mediaservices/contentKeyPolicies/getPolicyPropertiesWithSecrets/action`


---

#### `Media Services Streaming Endpoints Administrator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.Insights/metricDefinitions/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Media/mediaservices/*/read`
  - `Microsoft.Media/mediaservices/assets/listStreamingLocators/action`
  - `Microsoft.Media/mediaservices/streamingLocators/listPaths/action`
  - `Microsoft.Media/mediaservices/streamingEndpoints/*`


---

#### `Microsoft Sentinel Automation Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Logic/workflows/triggers/read`
  - `Microsoft.Logic/workflows/triggers/listCallbackUrl/action`
  - `Microsoft.Logic/workflows/runs/read`


---

#### `Microsoft Sentinel Contributor`


- Actions:
  - `Microsoft.SecurityInsights/*`
  - `Microsoft.OperationalInsights/workspaces/analytics/query/action`
  - `Microsoft.OperationalInsights/workspaces/*/read`
  - `Microsoft.OperationalInsights/workspaces/savedSearches/*`
  - `Microsoft.OperationsManagement/solutions/read`
  - `Microsoft.OperationalInsights/workspaces/query/read`
  - `Microsoft.OperationalInsights/workspaces/query/*/read`
  - `Microsoft.OperationalInsights/workspaces/dataSources/read`
  - `Microsoft.OperationalInsights/querypacks/*/read`
  - `Microsoft.Insights/workbooks/*`
  - `Microsoft.Insights/myworkbooks/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Microsoft Sentinel Reader`


- Actions:
  - `Microsoft.SecurityInsights/*/read`
  - `Microsoft.SecurityInsights/dataConnectorsCheckRequirements/action`
  - `Microsoft.SecurityInsights/threatIntelligence/indicators/query/action`
  - `Microsoft.SecurityInsights/threatIntelligence/queryIndicators/action`
  - `Microsoft.OperationalInsights/workspaces/analytics/query/action`
  - `Microsoft.OperationalInsights/workspaces/*/read`
  - `Microsoft.OperationalInsights/workspaces/LinkedServices/read`
  - `Microsoft.OperationalInsights/workspaces/savedSearches/read`
  - `Microsoft.OperationsManagement/solutions/read`
  - `Microsoft.OperationalInsights/workspaces/query/read`
  - `Microsoft.OperationalInsights/workspaces/query/*/read`
  - `Microsoft.OperationalInsights/querypacks/*/read`
  - `Microsoft.OperationalInsights/workspaces/dataSources/read`
  - `Microsoft.Insights/workbooks/read`
  - `Microsoft.Insights/myworkbooks/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Microsoft Sentinel Responder`


- Actions:
  - `Microsoft.SecurityInsights/*/read`
  - `Microsoft.SecurityInsights/dataConnectorsCheckRequirements/action`
  - `Microsoft.SecurityInsights/automationRules/*`
  - `Microsoft.SecurityInsights/cases/*`
  - `Microsoft.SecurityInsights/incidents/*`
  - `Microsoft.SecurityInsights/threatIntelligence/indicators/appendTags/action`
  - `Microsoft.SecurityInsights/threatIntelligence/indicators/query/action`
  - `Microsoft.SecurityInsights/threatIntelligence/bulkTag/action`
  - `Microsoft.SecurityInsights/threatIntelligence/indicators/appendTags/action`
  - `Microsoft.SecurityInsights/threatIntelligence/indicators/replaceTags/action`
  - `Microsoft.SecurityInsights/threatIntelligence/queryIndicators/action`
  - `Microsoft.OperationalInsights/workspaces/analytics/query/action`
  - `Microsoft.OperationalInsights/workspaces/*/read`
  - `Microsoft.OperationalInsights/workspaces/dataSources/read`
  - `Microsoft.OperationalInsights/workspaces/savedSearches/read`
  - `Microsoft.OperationsManagement/solutions/read`
  - `Microsoft.OperationalInsights/workspaces/query/read`
  - `Microsoft.OperationalInsights/workspaces/query/*/read`
  - `Microsoft.OperationalInsights/workspaces/dataSources/read`
  - `Microsoft.OperationalInsights/querypacks/*/read`
  - `Microsoft.Insights/workbooks/read`
  - `Microsoft.Insights/myworkbooks/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`

- NotActions:
  - `Microsoft.SecurityInsights/cases/*/Delete`
  - `Microsoft.SecurityInsights/incidents/*/Delete`


---

#### `Microsoft.Kubernetes connected cluster role`


- Actions:
  - `Microsoft.Kubernetes/connectedClusters/read`
  - `Microsoft.Kubernetes/connectedClusters/write`
  - `Microsoft.Kubernetes/connectedClusters/delete`
  - `Microsoft.Kubernetes/registeredSubscriptions/read`


---

#### `Monitoring Contributor`


- Actions:
  - `*/read`
  - `Microsoft.AlertsManagement/alerts/*`
  - `Microsoft.AlertsManagement/alertsSummary/*`
  - `Microsoft.Insights/actiongroups/*`
  - `Microsoft.Insights/activityLogAlerts/*`
  - `Microsoft.Insights/AlertRules/*`
  - `Microsoft.Insights/components/*`
  - `Microsoft.Insights/dataCollectionEndpoints/*`
  - `Microsoft.Insights/dataCollectionRules/*`
  - `Microsoft.Insights/dataCollectionRuleAssociations/*`
  - `Microsoft.Insights/DiagnosticSettings/*`
  - `Microsoft.Insights/eventtypes/*`
  - `Microsoft.Insights/LogDefinitions/*`
  - `Microsoft.Insights/metricalerts/*`
  - `Microsoft.Insights/MetricDefinitions/*`
  - `Microsoft.Insights/Metrics/*`
  - `Microsoft.Insights/Register/Action`
  - `Microsoft.Insights/scheduledqueryrules/*`
  - `Microsoft.Insights/webtests/*`
  - `Microsoft.Insights/workbooks/*`
  - `Microsoft.Insights/workbooktemplates/*`
  - `Microsoft.Insights/privateLinkScopes/*`
  - `Microsoft.Insights/privateLinkScopeOperationStatuses/*`
  - `Microsoft.OperationalInsights/workspaces/write`
  - `Microsoft.OperationalInsights/workspaces/intelligencepacks/*`
  - `Microsoft.OperationalInsights/workspaces/savedSearches/*`
  - `Microsoft.OperationalInsights/workspaces/search/action`
  - `Microsoft.OperationalInsights/workspaces/sharedKeys/action`
  - `Microsoft.OperationalInsights/workspaces/storageinsightconfigs/*`
  - `Microsoft.Support/*`
  - `Microsoft.WorkloadMonitor/monitors/*`
  - `Microsoft.AlertsManagement/smartDetectorAlertRules/*`
  - `Microsoft.AlertsManagement/actionRules/*`
  - `Microsoft.AlertsManagement/smartGroups/*`


---

#### `Monitoring Metrics Publisher`


- Actions:
  - `Microsoft.Insights/Register/Action`
  - `Microsoft.Support/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`

- DataActions:
  - `Microsoft.Insights/Metrics/Write`
  - `Microsoft.Insights/Telemetry/Write`


---

#### `Monitoring Reader`


- Actions:
  - `*/read`
  - `Microsoft.OperationalInsights/workspaces/search/action`
  - `Microsoft.Support/*`


---

#### `Network Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Network/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `New Relic APM Account Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `NewRelic.APM/accounts/*`


---

#### `Object Anchors Account Owner`


- DataActions:
  - `Microsoft.MixedReality/ObjectAnchorsAccounts/ingest/action`
  - `Microsoft.MixedReality/ObjectAnchorsAccounts/ingest/read`


---

#### `Object Anchors Account Reader`


- DataActions:
  - `Microsoft.MixedReality/ObjectAnchorsAccounts/ingest/read`


---

#### `Object Understanding Account Owner`


- DataActions:
  - `Microsoft.MixedReality/ObjectUnderstandingAccounts/ingest/action`
  - `Microsoft.MixedReality/ObjectUnderstandingAccounts/ingest/read`


---

#### `Object Understanding Account Reader`


- DataActions:
  - `Microsoft.MixedReality/ObjectUnderstandingAccounts/ingest/read`


---

#### `Owner`


- Actions:
  - `*`


---

#### `PlayFab Contributor`


- Actions:
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.PlayFab/*/read`
  - `Microsoft.PlayFab/*/write`
  - `Microsoft.PlayFab/*/delete`


---

#### `PlayFab Reader`


- Actions:
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.PlayFab/*/read`


---

#### `Policy Insights Data Writer (Preview)`


- Actions:
  - `Microsoft.Authorization/policyassignments/read`
  - `Microsoft.Authorization/policydefinitions/read`
  - `Microsoft.Authorization/policyexemptions/read`
  - `Microsoft.Authorization/policysetdefinitions/read`

- DataActions:
  - `Microsoft.PolicyInsights/checkDataPolicyCompliance/action`
  - `Microsoft.PolicyInsights/policyEvents/logDataEvents/action`


---

#### `Private DNS Zone Contributor`


- Actions:
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Network/privateDnsZones/*`
  - `Microsoft.Network/privateDnsOperationResults/*`
  - `Microsoft.Network/privateDnsOperationStatuses/*`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.Network/virtualNetworks/join/action`
  - `Microsoft.Authorization/*/read`


---

#### `Project Babylon Data Curator`


- Actions:
  - `Microsoft.ProjectBabylon/accounts/read`

- DataActions:
  - `Microsoft.ProjectBabylon/accounts/data/read`
  - `Microsoft.ProjectBabylon/accounts/data/write`


---

#### `Project Babylon Data Reader`


- Actions:
  - `Microsoft.ProjectBabylon/accounts/read`

- DataActions:
  - `Microsoft.ProjectBabylon/accounts/data/read`


---

#### `Project Babylon Data Source Administrator`


- Actions:
  - `Microsoft.ProjectBabylon/accounts/read`

- DataActions:
  - `Microsoft.ProjectBabylon/accounts/scan/read`
  - `Microsoft.ProjectBabylon/accounts/scan/write`


---

#### `Purview role 1 (Deprecated)`


- Actions:
  - `Microsoft.Purview/accounts/read`

- DataActions:
  - `Microsoft.Purview/accounts/data/read`
  - `Microsoft.Purview/accounts/data/write`


---

#### `Purview role 2 (Deprecated)`


- Actions:
  - `Microsoft.Purview/accounts/read`

- DataActions:
  - `Microsoft.Purview/accounts/scan/read`
  - `Microsoft.Purview/accounts/scan/write`


---

#### `Purview role 3 (Deprecated)`


- Actions:
  - `Microsoft.Purview/accounts/read`

- DataActions:
  - `Microsoft.Purview/accounts/data/read`


---

#### `Quota Request Operator`


- Actions:
  - `Microsoft.Capacity/resourceProviders/locations/serviceLimits/read`
  - `Microsoft.Capacity/resourceProviders/locations/serviceLimits/write`
  - `Microsoft.Capacity/resourceProviders/locations/serviceLimitsRequests/read`
  - `Microsoft.Capacity/register/action`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Reader`


- Actions:
  - `*/read`


---

#### `Reader and Data Access`


- Actions:
  - `Microsoft.Storage/storageAccounts/listKeys/action`
  - `Microsoft.Storage/storageAccounts/ListAccountSas/action`
  - `Microsoft.Storage/storageAccounts/read`


---

#### `Redis Cache Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Cache/register/action`
  - `Microsoft.Cache/redis/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Remote Rendering Administrator`


- DataActions:
  - `Microsoft.MixedReality/RemoteRenderingAccounts/convert/action`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/convert/read`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/convert/delete`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/managesessions/read`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/managesessions/action`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/managesessions/delete`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/render/read`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/diagnostic/read`


---

#### `Remote Rendering Client`


- DataActions:
  - `Microsoft.MixedReality/RemoteRenderingAccounts/managesessions/read`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/managesessions/action`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/managesessions/delete`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/render/read`
  - `Microsoft.MixedReality/RemoteRenderingAccounts/diagnostic/read`


---

#### `Reservation Purchaser`


- Actions:
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Capacity/register/action`
  - `Microsoft.Compute/register/action`
  - `Microsoft.SQL/register/action`
  - `Microsoft.Consumption/register/action`
  - `Microsoft.Capacity/catalogs/read`
  - `Microsoft.Authorization/roleAssignments/read`
  - `Microsoft.Consumption/reservationRecommendations/read`
  - `Microsoft.Support/supporttickets/write`


---

#### `Resource Policy Contributor`


- Actions:
  - `*/read`
  - `Microsoft.Authorization/policyassignments/*`
  - `Microsoft.Authorization/policydefinitions/*`
  - `Microsoft.Authorization/policyexemptions/*`
  - `Microsoft.Authorization/policysetdefinitions/*`
  - `Microsoft.PolicyInsights/*`
  - `Microsoft.Support/*`


---

#### `Scheduler Job Collections Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Scheduler/jobcollections/*`
  - `Microsoft.Support/*`


---

#### `Schema Registry Contributor (Preview)`


- Actions:
  - `Microsoft.EventHub/namespaces/schemagroups/*`

- DataActions:
  - `Microsoft.EventHub/namespaces/schemas/*`


---

#### `Schema Registry Reader (Preview)`


- Actions:
  - `Microsoft.EventHub/namespaces/schemagroups/read`

- DataActions:
  - `Microsoft.EventHub/namespaces/schemas/read`


---

#### `Search Index Data Contributor`


- DataActions:
  - `Microsoft.Search/searchServices/indexes/documents/*`


---

#### `Search Index Data Reader`


- DataActions:
  - `Microsoft.Search/searchServices/indexes/documents/read`


---

#### `Search Service Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Search/searchServices/*`
  - `Microsoft.Support/*`


---

#### `Security Admin`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Authorization/policyAssignments/*`
  - `Microsoft.Authorization/policyDefinitions/*`
  - `Microsoft.Authorization/policyExemptions/*`
  - `Microsoft.Authorization/policySetDefinitions/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Management/managementGroups/read`
  - `Microsoft.operationalInsights/workspaces/*/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Security/*`
  - `Microsoft.IoTSecurity/*`
  - `Microsoft.Support/*`


---

#### `Security Assessment Contributor`


- Actions:
  - `Microsoft.Security/assessments/write`


---

#### `Security Detonation Chamber Publisher`


- DataActions:
  - `Microsoft.SecurityDetonation/chambers/platforms/read`
  - `Microsoft.SecurityDetonation/chambers/platforms/write`
  - `Microsoft.SecurityDetonation/chambers/platforms/delete`
  - `Microsoft.SecurityDetonation/chambers/platforms/metadata/read`
  - `Microsoft.SecurityDetonation/chambers/workflows/read`
  - `Microsoft.SecurityDetonation/chambers/workflows/write`
  - `Microsoft.SecurityDetonation/chambers/workflows/delete`
  - `Microsoft.SecurityDetonation/chambers/workflows/metadata/read`
  - `Microsoft.SecurityDetonation/chambers/toolsets/read`
  - `Microsoft.SecurityDetonation/chambers/toolsets/write`
  - `Microsoft.SecurityDetonation/chambers/toolsets/delete`
  - `Microsoft.SecurityDetonation/chambers/toolsets/metadata/read`
  - `Microsoft.SecurityDetonation/chambers/publishRequests/read`
  - `Microsoft.SecurityDetonation/chambers/publishRequests/cancel/action`


---

#### `Security Detonation Chamber Reader`


- DataActions:
  - `Microsoft.SecurityDetonation/chambers/submissions/read`
  - `Microsoft.SecurityDetonation/chambers/submissions/files/read`


---

#### `Security Detonation Chamber Submission Manager`


- DataActions:
  - `Microsoft.SecurityDetonation/chambers/submissions/delete`
  - `Microsoft.SecurityDetonation/chambers/submissions/write`
  - `Microsoft.SecurityDetonation/chambers/submissions/read`
  - `Microsoft.SecurityDetonation/chambers/submissions/files/read`
  - `Microsoft.SecurityDetonation/chambers/submissions/accesskeyview/read`
  - `Microsoft.SecurityDetonation/chambers/submissions/adminview/read`
  - `Microsoft.SecurityDetonation/chambers/submissions/analystview/read`
  - `Microsoft.SecurityDetonation/chambers/submissions/publicview/read`
  - `Microsoft.SecurityDetonation/chambers/platforms/metadata/read`
  - `Microsoft.SecurityDetonation/chambers/workflows/metadata/read`
  - `Microsoft.SecurityDetonation/chambers/toolsets/metadata/read`


---

#### `Security Detonation Chamber Submitter`


- DataActions:
  - `Microsoft.SecurityDetonation/chambers/submissions/delete`
  - `Microsoft.SecurityDetonation/chambers/submissions/write`
  - `Microsoft.SecurityDetonation/chambers/submissions/read`
  - `Microsoft.SecurityDetonation/chambers/submissions/files/read`
  - `Microsoft.SecurityDetonation/chambers/submissions/accesskeyview/read`
  - `Microsoft.SecurityDetonation/chambers/platforms/metadata/read`
  - `Microsoft.SecurityDetonation/chambers/workflows/metadata/read`
  - `Microsoft.SecurityDetonation/chambers/toolsets/metadata/read`


---

#### `Security Manager (Legacy)`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.ClassicCompute/*/read`
  - `Microsoft.ClassicCompute/virtualMachines/*/write`
  - `Microsoft.ClassicNetwork/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Security/*`
  - `Microsoft.Support/*`


---

#### `Security Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/read`
  - `Microsoft.operationalInsights/workspaces/*/read`
  - `Microsoft.Resources/deployments/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Security/*/read`
  - `Microsoft.IoTSecurity/*/read`
  - `Microsoft.Support/*/read`
  - `Microsoft.Security/iotDefenderSettings/packageDownloads/action`
  - `Microsoft.Security/iotDefenderSettings/downloadManagerActivation/action`
  - `Microsoft.Security/iotSensors/downloadResetPassword/action`
  - `Microsoft.IoTSecurity/defenderSettings/packageDownloads/action`
  - `Microsoft.IoTSecurity/defenderSettings/downloadManagerActivation/action`
  - `Microsoft.Management/managementGroups/read`


---

#### `Services Hub Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.ServicesHub/connectors/write`
  - `Microsoft.ServicesHub/connectors/read`
  - `Microsoft.ServicesHub/connectors/delete`
  - `Microsoft.ServicesHub/connectors/checkAssessmentEntitlement/action`
  - `Microsoft.ServicesHub/supportOfferingEntitlement/read`
  - `Microsoft.ServicesHub/workspaces/read`


---

#### `SignalR AccessKey Reader`


- Actions:
  - `Microsoft.SignalRService/*/read`
  - `Microsoft.SignalRService/SignalR/listkeys/action`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `SignalR App Server`


- DataActions:
  - `Microsoft.SignalRService/SignalR/auth/accessKey/action`
  - `Microsoft.SignalRService/SignalR/serverConnection/write`
  - `Microsoft.SignalRService/SignalR/clientConnection/write`


---

#### `SignalR REST API Owner`


- DataActions:
  - `Microsoft.SignalRService/SignalR/auth/clientToken/action`
  - `Microsoft.SignalRService/SignalR/hub/send/action`
  - `Microsoft.SignalRService/SignalR/group/send/action`
  - `Microsoft.SignalRService/SignalR/group/read`
  - `Microsoft.SignalRService/SignalR/group/write`
  - `Microsoft.SignalRService/SignalR/clientConnection/send/action`
  - `Microsoft.SignalRService/SignalR/clientConnection/read`
  - `Microsoft.SignalRService/SignalR/clientConnection/write`
  - `Microsoft.SignalRService/SignalR/user/send/action`
  - `Microsoft.SignalRService/SignalR/user/read`
  - `Microsoft.SignalRService/SignalR/user/write`


---

#### `SignalR REST API Reader`


- DataActions:
  - `Microsoft.SignalRService/SignalR/group/read`
  - `Microsoft.SignalRService/SignalR/clientConnection/read`
  - `Microsoft.SignalRService/SignalR/user/read`


---

#### `SignalR Service Owner`


- DataActions:
  - `Microsoft.SignalRService/SignalR/auth/accessKey/action`
  - `Microsoft.SignalRService/SignalR/auth/clientToken/action`
  - `Microsoft.SignalRService/SignalR/hub/send/action`
  - `Microsoft.SignalRService/SignalR/group/send/action`
  - `Microsoft.SignalRService/SignalR/group/read`
  - `Microsoft.SignalRService/SignalR/group/write`
  - `Microsoft.SignalRService/SignalR/clientConnection/send/action`
  - `Microsoft.SignalRService/SignalR/clientConnection/read`
  - `Microsoft.SignalRService/SignalR/clientConnection/write`
  - `Microsoft.SignalRService/SignalR/serverConnection/write`
  - `Microsoft.SignalRService/SignalR/user/send/action`
  - `Microsoft.SignalRService/SignalR/user/read`
  - `Microsoft.SignalRService/SignalR/user/write`


---

#### `SignalR/Web PubSub Contributor`


- Actions:
  - `Microsoft.SignalRService/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Support/*`


---

#### `Site Recovery Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.RecoveryServices/locations/allocatedStamp/read`
  - `Microsoft.RecoveryServices/locations/allocateStamp/action`
  - `Microsoft.RecoveryServices/Vaults/certificates/write`
  - `Microsoft.RecoveryServices/Vaults/extendedInformation/*`
  - `Microsoft.RecoveryServices/Vaults/read`
  - `Microsoft.RecoveryServices/Vaults/refreshContainers/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/*`
  - `Microsoft.RecoveryServices/vaults/replicationAlertSettings/*`
  - `Microsoft.RecoveryServices/vaults/replicationEvents/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/*`
  - `Microsoft.RecoveryServices/vaults/replicationJobs/*`
  - `Microsoft.RecoveryServices/vaults/replicationPolicies/*`
  - `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans/*`
  - `Microsoft.RecoveryServices/vaults/replicationVaultSettings/*`
  - `Microsoft.RecoveryServices/Vaults/storageConfig/*`
  - `Microsoft.RecoveryServices/Vaults/tokenInfo/read`
  - `Microsoft.RecoveryServices/Vaults/usages/read`
  - `Microsoft.RecoveryServices/Vaults/vaultTokens/read`
  - `Microsoft.RecoveryServices/Vaults/monitoringAlerts/*`
  - `Microsoft.RecoveryServices/Vaults/monitoringConfigurations/notificationConfiguration/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/storageAccounts/read`
  - `Microsoft.RecoveryServices/vaults/replicationOperationStatus/read`
  - `Microsoft.Support/*`


---

#### `Site Recovery Operator`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.RecoveryServices/locations/allocatedStamp/read`
  - `Microsoft.RecoveryServices/locations/allocateStamp/action`
  - `Microsoft.RecoveryServices/Vaults/extendedInformation/read`
  - `Microsoft.RecoveryServices/Vaults/read`
  - `Microsoft.RecoveryServices/Vaults/refreshContainers/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/read`
  - `Microsoft.RecoveryServices/vaults/replicationAlertSettings/read`
  - `Microsoft.RecoveryServices/vaults/replicationEvents/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/checkConsistency/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/reassociateGateway/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/renewcertificate/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationNetworks/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationNetworks/replicationNetworkMappings/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectableItems/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/applyRecoveryPoint/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/failoverCommit/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/plannedFailover/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/recoveryPoints/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/repairReplication/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/reProtect/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/switchprotection/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/testFailover/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/testFailoverCleanup/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/unplannedFailover/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/updateMobilityService/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectionContainerMappings/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationRecoveryServicesProviders/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationRecoveryServicesProviders/refreshProvider/action`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationStorageClassifications/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationStorageClassifications/replicationStorageClassificationMappings/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationvCenters/read`
  - `Microsoft.RecoveryServices/vaults/replicationJobs/*`
  - `Microsoft.RecoveryServices/vaults/replicationPolicies/read`
  - `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans/failoverCommit/action`
  - `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans/plannedFailover/action`
  - `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans/read`
  - `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans/reProtect/action`
  - `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans/testFailover/action`
  - `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans/testFailoverCleanup/action`
  - `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans/unplannedFailover/action`
  - `Microsoft.RecoveryServices/vaults/replicationVaultSettings/read`
  - `Microsoft.RecoveryServices/Vaults/monitoringAlerts/*`
  - `Microsoft.RecoveryServices/Vaults/monitoringConfigurations/notificationConfiguration/read`
  - `Microsoft.RecoveryServices/Vaults/storageConfig/read`
  - `Microsoft.RecoveryServices/Vaults/tokenInfo/read`
  - `Microsoft.RecoveryServices/Vaults/usages/read`
  - `Microsoft.RecoveryServices/Vaults/vaultTokens/read`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/storageAccounts/read`
  - `Microsoft.Support/*`


---

#### `Site Recovery Reader`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.RecoveryServices/locations/allocatedStamp/read`
  - `Microsoft.RecoveryServices/Vaults/extendedInformation/read`
  - `Microsoft.RecoveryServices/Vaults/monitoringAlerts/read`
  - `Microsoft.RecoveryServices/Vaults/monitoringConfigurations/notificationConfiguration/read`
  - `Microsoft.RecoveryServices/Vaults/read`
  - `Microsoft.RecoveryServices/Vaults/refreshContainers/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/operationResults/read`
  - `Microsoft.RecoveryServices/Vaults/registeredIdentities/read`
  - `Microsoft.RecoveryServices/vaults/replicationAlertSettings/read`
  - `Microsoft.RecoveryServices/vaults/replicationEvents/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationNetworks/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationNetworks/replicationNetworkMappings/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectableItems/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/recoveryPoints/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectionContainerMappings/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationRecoveryServicesProviders/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationStorageClassifications/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationStorageClassifications/replicationStorageClassificationMappings/read`
  - `Microsoft.RecoveryServices/vaults/replicationFabrics/replicationvCenters/read`
  - `Microsoft.RecoveryServices/vaults/replicationJobs/read`
  - `Microsoft.RecoveryServices/vaults/replicationPolicies/read`
  - `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans/read`
  - `Microsoft.RecoveryServices/vaults/replicationVaultSettings/read`
  - `Microsoft.RecoveryServices/Vaults/storageConfig/read`
  - `Microsoft.RecoveryServices/Vaults/tokenInfo/read`
  - `Microsoft.RecoveryServices/Vaults/usages/read`
  - `Microsoft.RecoveryServices/Vaults/vaultTokens/read`
  - `Microsoft.Support/*`


---

#### `Spatial Anchors Account Contributor`


- DataActions:
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/create/action`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/discovery/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/properties/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/query/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/submitdiag/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/write`


---

#### `Spatial Anchors Account Owner`


- DataActions:
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/create/action`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/delete`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/discovery/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/properties/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/query/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/submitdiag/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/write`


---

#### `Spatial Anchors Account Reader`


- DataActions:
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/discovery/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/properties/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/query/read`
  - `Microsoft.MixedReality/SpatialAnchorsAccounts/submitdiag/read`


---

#### `SQL DB Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Sql/locations/*/read`
  - `Microsoft.Sql/servers/databases/*`
  - `Microsoft.Sql/servers/read`
  - `Microsoft.Support/*`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.Insights/metricDefinitions/read`

- NotActions:
  - `Microsoft.Sql/servers/databases/ledgerDigestUploads/write`
  - `Microsoft.Sql/servers/databases/ledgerDigestUploads/disable/action`
  - `Microsoft.Sql/managedInstances/databases/currentSensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/recommendedSensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/schemas/tables/columns/sensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/securityAlertPolicies/*`
  - `Microsoft.Sql/managedInstances/databases/sensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/vulnerabilityAssessments/*`
  - `Microsoft.Sql/managedInstances/securityAlertPolicies/*`
  - `Microsoft.Sql/managedInstances/vulnerabilityAssessments/*`
  - `Microsoft.Sql/servers/databases/auditingSettings/*`
  - `Microsoft.Sql/servers/databases/auditRecords/read`
  - `Microsoft.Sql/servers/databases/currentSensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/dataMaskingPolicies/*`
  - `Microsoft.Sql/servers/databases/extendedAuditingSettings/*`
  - `Microsoft.Sql/servers/databases/recommendedSensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/schemas/tables/columns/sensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/securityAlertPolicies/*`
  - `Microsoft.Sql/servers/databases/securityMetrics/*`
  - `Microsoft.Sql/servers/databases/sensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/vulnerabilityAssessments/*`
  - `Microsoft.Sql/servers/databases/vulnerabilityAssessmentScans/*`
  - `Microsoft.Sql/servers/databases/vulnerabilityAssessmentSettings/*`
  - `Microsoft.Sql/servers/vulnerabilityAssessments/*`


---

#### `SQL Managed Instance Contributor`


- Actions:
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Network/networkSecurityGroups/*`
  - `Microsoft.Network/routeTables/*`
  - `Microsoft.Sql/locations/*/read`
  - `Microsoft.Sql/locations/instanceFailoverGroups/*`
  - `Microsoft.Sql/managedInstances/*`
  - `Microsoft.Support/*`
  - `Microsoft.Network/virtualNetworks/subnets/*`
  - `Microsoft.Network/virtualNetworks/*`
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.Insights/metricDefinitions/read`

- NotActions:
  - `Microsoft.Sql/managedInstances/azureADOnlyAuthentications/delete`
  - `Microsoft.Sql/managedInstances/azureADOnlyAuthentications/write`


---

#### `SQL Security Manager`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Sql/locations/administratorAzureAsyncOperation/read`
  - `Microsoft.Sql/managedInstances/databases/currentSensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/recommendedSensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/schemas/tables/columns/sensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/securityAlertPolicies/*`
  - `Microsoft.Sql/managedInstances/databases/sensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/vulnerabilityAssessments/*`
  - `Microsoft.Sql/managedInstances/securityAlertPolicies/*`
  - `Microsoft.Sql/managedInstances/databases/transparentDataEncryption/*`
  - `Microsoft.Sql/managedInstances/vulnerabilityAssessments/*`
  - `Microsoft.Sql/servers/auditingSettings/*`
  - `Microsoft.Sql/servers/extendedAuditingSettings/read`
  - `Microsoft.Sql/servers/databases/auditingSettings/*`
  - `Microsoft.Sql/servers/databases/auditRecords/read`
  - `Microsoft.Sql/servers/databases/currentSensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/dataMaskingPolicies/*`
  - `Microsoft.Sql/servers/databases/extendedAuditingSettings/read`
  - `Microsoft.Sql/servers/databases/read`
  - `Microsoft.Sql/servers/databases/recommendedSensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/schemas/read`
  - `Microsoft.Sql/servers/databases/schemas/tables/columns/read`
  - `Microsoft.Sql/servers/databases/schemas/tables/columns/sensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/schemas/tables/read`
  - `Microsoft.Sql/servers/databases/securityAlertPolicies/*`
  - `Microsoft.Sql/servers/databases/securityMetrics/*`
  - `Microsoft.Sql/servers/databases/sensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/transparentDataEncryption/*`
  - `Microsoft.Sql/servers/databases/vulnerabilityAssessments/*`
  - `Microsoft.Sql/servers/databases/vulnerabilityAssessmentScans/*`
  - `Microsoft.Sql/servers/databases/vulnerabilityAssessmentSettings/*`
  - `Microsoft.Sql/servers/devOpsAuditingSettings/*`
  - `Microsoft.Sql/servers/firewallRules/*`
  - `Microsoft.Sql/servers/read`
  - `Microsoft.Sql/servers/securityAlertPolicies/*`
  - `Microsoft.Sql/servers/vulnerabilityAssessments/*`
  - `Microsoft.Support/*`
  - `Microsoft.Sql/servers/azureADOnlyAuthentications/*`
  - `Microsoft.Sql/managedInstances/read`
  - `Microsoft.Sql/managedInstances/azureADOnlyAuthentications/*`
  - `Microsoft.Security/sqlVulnerabilityAssessments/*`
  - `Microsoft.Sql/managedInstances/administrators/read`
  - `Microsoft.Sql/servers/administrators/read`


---

#### `SQL Server Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Sql/locations/*/read`
  - `Microsoft.Sql/servers/*`
  - `Microsoft.Support/*`
  - `Microsoft.Insights/metrics/read`
  - `Microsoft.Insights/metricDefinitions/read`

- NotActions:
  - `Microsoft.Sql/managedInstances/databases/currentSensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/recommendedSensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/schemas/tables/columns/sensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/securityAlertPolicies/*`
  - `Microsoft.Sql/managedInstances/databases/sensitivityLabels/*`
  - `Microsoft.Sql/managedInstances/databases/vulnerabilityAssessments/*`
  - `Microsoft.Sql/managedInstances/securityAlertPolicies/*`
  - `Microsoft.Sql/managedInstances/vulnerabilityAssessments/*`
  - `Microsoft.Sql/servers/auditingSettings/*`
  - `Microsoft.Sql/servers/databases/auditingSettings/*`
  - `Microsoft.Sql/servers/databases/auditRecords/read`
  - `Microsoft.Sql/servers/databases/currentSensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/dataMaskingPolicies/*`
  - `Microsoft.Sql/servers/databases/extendedAuditingSettings/*`
  - `Microsoft.Sql/servers/databases/recommendedSensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/schemas/tables/columns/sensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/securityAlertPolicies/*`
  - `Microsoft.Sql/servers/databases/securityMetrics/*`
  - `Microsoft.Sql/servers/databases/sensitivityLabels/*`
  - `Microsoft.Sql/servers/databases/vulnerabilityAssessments/*`
  - `Microsoft.Sql/servers/databases/vulnerabilityAssessmentScans/*`
  - `Microsoft.Sql/servers/databases/vulnerabilityAssessmentSettings/*`
  - `Microsoft.Sql/servers/devOpsAuditingSettings/*`
  - `Microsoft.Sql/servers/extendedAuditingSettings/*`
  - `Microsoft.Sql/servers/securityAlertPolicies/*`
  - `Microsoft.Sql/servers/vulnerabilityAssessments/*`
  - `Microsoft.Sql/servers/azureADOnlyAuthentications/delete`
  - `Microsoft.Sql/servers/azureADOnlyAuthentications/write`


---

#### `Storage Account Backup Contributor Role`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Authorization/locks/read`
  - `Microsoft.Authorization/locks/write`
  - `Microsoft.Authorization/locks/delete`
  - `Microsoft.Features/features/read`
  - `Microsoft.Features/providers/features/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/operations/read`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/read`
  - `Microsoft.Storage/storageAccounts/blobServices/read`
  - `Microsoft.Storage/storageAccounts/blobServices/write`
  - `Microsoft.Storage/storageAccounts/read`
  - `Microsoft.Storage/storageAccounts/restoreBlobRanges/action`


---

#### `Storage Account Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/diagnosticSettings/*`
  - `Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Storage/storageAccounts/*`
  - `Microsoft.Support/*`


---

#### `Storage Account Key Operator Service Role`


- Actions:
  - `Microsoft.Storage/storageAccounts/listkeys/action`
  - `Microsoft.Storage/storageAccounts/regeneratekey/action`


---

#### `Storage Blob Data Contributor`


- Actions:
  - `Microsoft.Storage/storageAccounts/blobServices/containers/delete`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/read`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/write`
  - `Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action`

- DataActions:
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action`
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action`


---

#### `Storage Blob Data Owner`


- Actions:
  - `Microsoft.Storage/storageAccounts/blobServices/containers/*`
  - `Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action`

- DataActions:
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*`


---

#### `Storage Blob Data Reader`


- Actions:
  - `Microsoft.Storage/storageAccounts/blobServices/containers/read`
  - `Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action`

- DataActions:
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`


---

#### `Storage Blob Delegator`


- Actions:
  - `Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action`


---

#### `Storage File Data SMB Share Contributor`


- DataActions:
  - `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read`
  - `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write`
  - `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/delete`


---

#### `Storage File Data SMB Share Elevated Contributor`


- DataActions:
  - `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read`
  - `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write`
  - `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/delete`
  - `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/modifypermissions/action`


---

#### `Storage File Data SMB Share Reader`


- DataActions:
  - `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read`


---

#### `Storage Queue Data Contributor`


- Actions:
  - `Microsoft.Storage/storageAccounts/queueServices/queues/delete`
  - `Microsoft.Storage/storageAccounts/queueServices/queues/read`
  - `Microsoft.Storage/storageAccounts/queueServices/queues/write`

- DataActions:
  - `Microsoft.Storage/storageAccounts/queueServices/queues/messages/delete`
  - `Microsoft.Storage/storageAccounts/queueServices/queues/messages/read`
  - `Microsoft.Storage/storageAccounts/queueServices/queues/messages/write`
  - `Microsoft.Storage/storageAccounts/queueServices/queues/messages/process/action`


---

#### `Storage Queue Data Message Processor`


- DataActions:
  - `Microsoft.Storage/storageAccounts/queueServices/queues/messages/read`
  - `Microsoft.Storage/storageAccounts/queueServices/queues/messages/process/action`


---

#### `Storage Queue Data Message Sender`


- DataActions:
  - `Microsoft.Storage/storageAccounts/queueServices/queues/messages/add/action`


---

#### `Storage Queue Data Reader`


- Actions:
  - `Microsoft.Storage/storageAccounts/queueServices/queues/read`

- DataActions:
  - `Microsoft.Storage/storageAccounts/queueServices/queues/messages/read`


---

#### `Storage Table Data Contributor`


- Actions:
  - `Microsoft.Storage/storageAccounts/tableServices/tables/read`
  - `Microsoft.Storage/storageAccounts/tableServices/tables/write`
  - `Microsoft.Storage/storageAccounts/tableServices/tables/delete`

- DataActions:
  - `Microsoft.Storage/storageAccounts/tableServices/tables/entities/read`
  - `Microsoft.Storage/storageAccounts/tableServices/tables/entities/write`
  - `Microsoft.Storage/storageAccounts/tableServices/tables/entities/delete`
  - `Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action`
  - `Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action`


---

#### `Storage Table Data Reader`


- Actions:
  - `Microsoft.Storage/storageAccounts/tableServices/tables/read`

- DataActions:
  - `Microsoft.Storage/storageAccounts/tableServices/tables/entities/read`


---

#### `Stream Analytics Query Tester`


- Actions:
  - `Microsoft.StreamAnalytics/locations/TestQuery/action`
  - `Microsoft.StreamAnalytics/locations/OperationResults/read`
  - `Microsoft.StreamAnalytics/locations/SampleInput/action`
  - `Microsoft.StreamAnalytics/locations/CompileQuery/action`


---

#### `Support Request Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `Tag Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/resources/read`
  - `Microsoft.Resources/subscriptions/resources/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Support/*`
  - `Microsoft.Resources/tags/*`


---

#### `Test Base Reader`


- Actions:
  - `Microsoft.TestBase/testBaseAccounts/packages/testResults/getDownloadUrl/action`
  - `Microsoft.TestBase/testBaseAccounts/packages/testResults/getVideoDownloadUrl/action`
  - `Microsoft.TestBase/testBaseAccounts/packages/getDownloadUrl/action`
  - `Microsoft.TestBase/*/read`
  - `Microsoft.TestBase/testBaseAccounts/customerEvents/write`
  - `Microsoft.TestBase/testBaseAccounts/customerEvents/delete`


---

#### `Traffic Manager Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Network/trafficManagerProfiles/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`


---

#### `User Access Administrator`


- Actions:
  - `*/read`
  - `Microsoft.Authorization/*`
  - `Microsoft.Support/*`


---

#### `Virtual Machine Administrator Login`


- Actions:
  - `Microsoft.Network/publicIPAddresses/read`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.Network/loadBalancers/read`
  - `Microsoft.Network/networkInterfaces/read`
  - `Microsoft.Compute/virtualMachines/*/read`
  - `Microsoft.HybridCompute/machines/*/read`
  - `Microsoft.HybridConnectivity/endpoints/listCredentials/action`

- DataActions:
  - `Microsoft.Compute/virtualMachines/login/action`
  - `Microsoft.Compute/virtualMachines/loginAsAdmin/action`
  - `Microsoft.HybridCompute/machines/login/action`
  - `Microsoft.HybridCompute/machines/loginAsAdmin/action`


---

#### `Virtual Machine Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Compute/availabilitySets/*`
  - `Microsoft.Compute/locations/*`
  - `Microsoft.Compute/virtualMachines/*`
  - `Microsoft.Compute/virtualMachineScaleSets/*`
  - `Microsoft.Compute/cloudServices/*`
  - `Microsoft.Compute/disks/write`
  - `Microsoft.Compute/disks/read`
  - `Microsoft.Compute/disks/delete`
  - `Microsoft.DevTestLab/schedules/*`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Network/applicationGateways/backendAddressPools/join/action`
  - `Microsoft.Network/loadBalancers/backendAddressPools/join/action`
  - `Microsoft.Network/loadBalancers/inboundNatPools/join/action`
  - `Microsoft.Network/loadBalancers/inboundNatRules/join/action`
  - `Microsoft.Network/loadBalancers/probes/join/action`
  - `Microsoft.Network/loadBalancers/read`
  - `Microsoft.Network/locations/*`
  - `Microsoft.Network/networkInterfaces/*`
  - `Microsoft.Network/networkSecurityGroups/join/action`
  - `Microsoft.Network/networkSecurityGroups/read`
  - `Microsoft.Network/publicIPAddresses/join/action`
  - `Microsoft.Network/publicIPAddresses/read`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.Network/virtualNetworks/subnets/join/action`
  - `Microsoft.RecoveryServices/locations/*`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/backupProtectionIntent/write`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/*/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/read`
  - `Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/write`
  - `Microsoft.RecoveryServices/Vaults/backupPolicies/read`
  - `Microsoft.RecoveryServices/Vaults/backupPolicies/write`
  - `Microsoft.RecoveryServices/Vaults/read`
  - `Microsoft.RecoveryServices/Vaults/usages/read`
  - `Microsoft.RecoveryServices/Vaults/write`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.SerialConsole/serialPorts/connect/action`
  - `Microsoft.SqlVirtualMachine/*`
  - `Microsoft.Storage/storageAccounts/listKeys/action`
  - `Microsoft.Storage/storageAccounts/read`
  - `Microsoft.Support/*`


---

#### `Virtual Machine User Login`


- Actions:
  - `Microsoft.Network/publicIPAddresses/read`
  - `Microsoft.Network/virtualNetworks/read`
  - `Microsoft.Network/loadBalancers/read`
  - `Microsoft.Network/networkInterfaces/read`
  - `Microsoft.Compute/virtualMachines/*/read`
  - `Microsoft.HybridCompute/machines/*/read`
  - `Microsoft.HybridConnectivity/endpoints/listCredentials/action`

- DataActions:
  - `Microsoft.Compute/virtualMachines/login/action`
  - `Microsoft.HybridCompute/machines/login/action`


---

#### `Web Plan Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Web/serverFarms/*`
  - `Microsoft.Web/hostingEnvironments/Join/Action`


---

#### `Web PubSub Service Owner (Preview)`


- DataActions:
  - `Microsoft.SignalRService/WebPubSub/*`


---

#### `Web PubSub Service Reader (Preview)`


- DataActions:
  - `Microsoft.SignalRService/WebPubSub/*/read`


---

#### `Website Contributor`


- Actions:
  - `Microsoft.Authorization/*/read`
  - `Microsoft.Insights/alertRules/*`
  - `Microsoft.Insights/components/*`
  - `Microsoft.ResourceHealth/availabilityStatuses/read`
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`
  - `Microsoft.Support/*`
  - `Microsoft.Web/certificates/*`
  - `Microsoft.Web/listSitesAssignedToHostName/read`
  - `Microsoft.Web/serverFarms/join/action`
  - `Microsoft.Web/serverFarms/read`
  - `Microsoft.Web/sites/*`


---

#### `Workbook Contributor`


- Actions:
  - `Microsoft.Insights/workbooks/write`
  - `Microsoft.Insights/workbooks/delete`
  - `Microsoft.Insights/workbooks/read`
  - `Microsoft.Insights/workbooktemplates/write`
  - `Microsoft.Insights/workbooktemplates/delete`
  - `Microsoft.Insights/workbooktemplates/read`


---

#### `Workbook Reader`


- Actions:
  - `microsoft.insights/workbooks/read`
  - `microsoft.insights/workbooktemplates/read`


---

#### `WorkloadBuilder Migration Agent Role`


- Actions:
  - `Microsoft.WorkloadBuilder/migrationAgents/Read`
  - `Microsoft.WorkloadBuilder/migrationAgents/Write`


---
    
### Azure AD Role Permissions

---

#### `Application Administrator`

- `microsoft.directory/applications/create`
- `microsoft.directory/applications/delete`
- `microsoft.directory/applications/applicationProxy/read`
- `microsoft.directory/applications/applicationProxy/update`
- `microsoft.directory/applications/applicationProxyAuthentication/update`
- `microsoft.directory/applications/applicationProxySslCertificate/update`
- `microsoft.directory/applications/applicationProxyUrlSettings/update`
- `microsoft.directory/applications/appRoles/update`
- `microsoft.directory/applications/audience/update`
- `microsoft.directory/applications/authentication/update`
- `microsoft.directory/applications/basic/update`
- `microsoft.directory/applications/credentials/update`
- `microsoft.directory/applications/extensionProperties/update`
- `microsoft.directory/applications/notes/update`
- `microsoft.directory/applications/owners/update`
- `microsoft.directory/applications/permissions/update`
- `microsoft.directory/applications/policies/update`
- `microsoft.directory/applications/tag/update`
- `microsoft.directory/applications/verification/update`
- `microsoft.directory/applications/synchronization/standard/read`
- `microsoft.directory/applicationTemplates/instantiate`
- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/connectors/create`
- `microsoft.directory/connectors/allProperties/read`
- `microsoft.directory/connectorGroups/create`
- `microsoft.directory/connectorGroups/delete`
- `microsoft.directory/connectorGroups/allProperties/read`
- `microsoft.directory/connectorGroups/allProperties/update`
- `microsoft.directory/customAuthenticationExtensions/allProperties/allTasks`
- `microsoft.directory/deletedItems.applications/delete`
- `microsoft.directory/deletedItems.applications/restore`
- `microsoft.directory/oAuth2PermissionGrants/allProperties/allTasks`
- `microsoft.directory/applicationPolicies/create`
- `microsoft.directory/applicationPolicies/delete`
- `microsoft.directory/applicationPolicies/standard/read`
- `microsoft.directory/applicationPolicies/owners/read`
- `microsoft.directory/applicationPolicies/policyAppliedTo/read`
- `microsoft.directory/applicationPolicies/basic/update`
- `microsoft.directory/applicationPolicies/owners/update`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/servicePrincipals/create`
- `microsoft.directory/servicePrincipals/delete`
- `microsoft.directory/servicePrincipals/disable`
- `microsoft.directory/servicePrincipals/enable`
- `microsoft.directory/servicePrincipals/getPasswordSingleSignOnCredentials`
- `microsoft.directory/servicePrincipals/synchronizationCredentials/manage`
- `microsoft.directory/servicePrincipals/synchronizationJobs/manage`
- `microsoft.directory/servicePrincipals/synchronizationSchema/manage`
- `microsoft.directory/servicePrincipals/managePasswordSingleSignOnCredentials`
- `microsoft.directory/servicePrincipals/managePermissionGrantsForAll.microsoft-application-admin`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`
- `microsoft.directory/servicePrincipals/audience/update`
- `microsoft.directory/servicePrincipals/authentication/update`
- `microsoft.directory/servicePrincipals/basic/update`
- `microsoft.directory/servicePrincipals/credentials/update`
- `microsoft.directory/servicePrincipals/notes/update`
- `microsoft.directory/servicePrincipals/owners/update`
- `microsoft.directory/servicePrincipals/permissions/update`
- `microsoft.directory/servicePrincipals/policies/update`
- `microsoft.directory/servicePrincipals/tag/update`
- `microsoft.directory/servicePrincipals/synchronization/standard/read`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Application Developer`

- `microsoft.directory/applications/createAsOwner`
- `microsoft.directory/oAuth2PermissionGrants/createAsOwner`
- `microsoft.directory/servicePrincipals/createAsOwner`

---

#### `Attack Payload Author`

- `microsoft.office365.protectionCenter/attackSimulator/payload/allProperties/allTasks`
- `microsoft.office365.protectionCenter/attackSimulator/reports/allProperties/read`

---

#### `Attack Simulation Administrator`

- `microsoft.office365.protectionCenter/attackSimulator/payload/allProperties/allTasks`
- `microsoft.office365.protectionCenter/attackSimulator/reports/allProperties/read`
- `microsoft.office365.protectionCenter/attackSimulator/simulation/allProperties/allTasks`

---

#### `Attribute Assignment Administrator`

- `microsoft.directory/attributeSets/allProperties/read`
- `microsoft.directory/customSecurityAttributeDefinitions/allProperties/read`
- `microsoft.directory/devices/customSecurityAttributes/read`
- `microsoft.directory/devices/customSecurityAttributes/update`
- `microsoft.directory/servicePrincipals/customSecurityAttributes/read`
- `microsoft.directory/servicePrincipals/customSecurityAttributes/update`
- `microsoft.directory/users/customSecurityAttributes/read`
- `microsoft.directory/users/customSecurityAttributes/update`

---

#### `Attribute Assignment Reader`

- `microsoft.directory/attributeSets/allProperties/read`
- `microsoft.directory/customSecurityAttributeDefinitions/allProperties/read`
- `microsoft.directory/devices/customSecurityAttributes/read`
- `microsoft.directory/servicePrincipals/customSecurityAttributes/read`
- `microsoft.directory/users/customSecurityAttributes/read`

---

#### `Attribute Definition Administrator`

- `microsoft.directory/attributeSets/allProperties/allTasks`
- `microsoft.directory/customSecurityAttributeDefinitions/allProperties/allTasks`

---

#### `Attribute Definition Reader`

- `microsoft.directory/attributeSets/allProperties/read`
- `microsoft.directory/customSecurityAttributeDefinitions/allProperties/read`

---

#### `Authentication Administrator`

- `microsoft.directory/users/authenticationMethods/create`
- `microsoft.directory/users/authenticationMethods/delete`
- `microsoft.directory/users/authenticationMethods/standard/restrictedRead`
- `microsoft.directory/users/authenticationMethods/basic/update`
- `microsoft.directory/users/invalidateAllRefreshTokens`
- `microsoft.directory/users/password/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Authentication Policy Administrator`

- `microsoft.directory/organization/strongAuthentication/allTasks`
- `microsoft.directory/userCredentialPolicies/create`
- `microsoft.directory/userCredentialPolicies/delete`
- `microsoft.directory/userCredentialPolicies/standard/read`
- `microsoft.directory/userCredentialPolicies/owners/read`
- `microsoft.directory/userCredentialPolicies/policyAppliedTo/read`
- `microsoft.directory/userCredentialPolicies/basic/update`
- `microsoft.directory/userCredentialPolicies/owners/update`
- `microsoft.directory/userCredentialPolicies/tenantDefault/update`
- `microsoft.directory/verifiableCredentials/configuration/contracts/cards/allProperties/read`
- `microsoft.directory/verifiableCredentials/configuration/contracts/cards/revoke`
- `microsoft.directory/verifiableCredentials/configuration/contracts/create`
- `microsoft.directory/verifiableCredentials/configuration/contracts/allProperties/read`
- `microsoft.directory/verifiableCredentials/configuration/contracts/allProperties/update`
- `microsoft.directory/verifiableCredentials/configuration/create`
- `microsoft.directory/verifiableCredentials/configuration/delete`
- `microsoft.directory/verifiableCredentials/configuration/allProperties/read`
- `microsoft.directory/verifiableCredentials/configuration/allProperties/update`
- `microsoft.azure.supportTickets/allEntities/allTasks`

---

#### `Azure AD Joined Device Local Administrator`

- `microsoft.directory/groupSettings/standard/read`
- `microsoft.directory/groupSettingTemplates/standard/read`

---

#### `Azure DevOps Administrator`

- `microsoft.azure.devOps/allEntities/allTasks`

---

#### `Azure Information Protection Administrator`

- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.azure.informationProtection/allEntities/allTasks`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `B2C IEF Keyset Administrator`

- `microsoft.directory/b2cTrustFrameworkKeySet/allProperties/allTasks`

---

#### `B2C IEF Policy Administrator`

- `microsoft.directory/b2cTrustFrameworkPolicy/allProperties/allTasks`

---

#### `Billing Administrator`

- `microsoft.directory/organization/basic/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.commerce.billing/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Cloud App Security Administrator`

- `microsoft.directory/cloudAppSecurity/allProperties/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Cloud Application Administrator`

- `microsoft.directory/applications/create`
- `microsoft.directory/applications/delete`
- `microsoft.directory/applications/appRoles/update`
- `microsoft.directory/applications/audience/update`
- `microsoft.directory/applications/authentication/update`
- `microsoft.directory/applications/basic/update`
- `microsoft.directory/applications/credentials/update`
- `microsoft.directory/applications/extensionProperties/update`
- `microsoft.directory/applications/notes/update`
- `microsoft.directory/applications/owners/update`
- `microsoft.directory/applications/permissions/update`
- `microsoft.directory/applications/policies/update`
- `microsoft.directory/applications/tag/update`
- `microsoft.directory/applications/verification/update`
- `microsoft.directory/applications/synchronization/standard/read`
- `microsoft.directory/applicationTemplates/instantiate`
- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/deletedItems.applications/delete`
- `microsoft.directory/deletedItems.applications/restore`
- `microsoft.directory/oAuth2PermissionGrants/allProperties/allTasks`
- `microsoft.directory/applicationPolicies/create`
- `microsoft.directory/applicationPolicies/delete`
- `microsoft.directory/applicationPolicies/standard/read`
- `microsoft.directory/applicationPolicies/owners/read`
- `microsoft.directory/applicationPolicies/policyAppliedTo/read`
- `microsoft.directory/applicationPolicies/basic/update`
- `microsoft.directory/applicationPolicies/owners/update`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/servicePrincipals/create`
- `microsoft.directory/servicePrincipals/delete`
- `microsoft.directory/servicePrincipals/disable`
- `microsoft.directory/servicePrincipals/enable`
- `microsoft.directory/servicePrincipals/getPasswordSingleSignOnCredentials`
- `microsoft.directory/servicePrincipals/synchronizationCredentials/manage`
- `microsoft.directory/servicePrincipals/synchronizationJobs/manage`
- `microsoft.directory/servicePrincipals/synchronizationSchema/manage`
- `microsoft.directory/servicePrincipals/managePasswordSingleSignOnCredentials`
- `microsoft.directory/servicePrincipals/managePermissionGrantsForAll.microsoft-application-admin`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`
- `microsoft.directory/servicePrincipals/audience/update`
- `microsoft.directory/servicePrincipals/authentication/update`
- `microsoft.directory/servicePrincipals/basic/update`
- `microsoft.directory/servicePrincipals/credentials/update`
- `microsoft.directory/servicePrincipals/notes/update`
- `microsoft.directory/servicePrincipals/owners/update`
- `microsoft.directory/servicePrincipals/permissions/update`
- `microsoft.directory/servicePrincipals/policies/update`
- `microsoft.directory/servicePrincipals/tag/update`
- `microsoft.directory/servicePrincipals/synchronization/standard/read`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Cloud Device Administrator`

- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/bitlockerKeys/key/read`
- `microsoft.directory/devices/delete`
- `microsoft.directory/devices/disable`
- `microsoft.directory/devices/enable`
- `microsoft.directory/deviceManagementPolicies/standard/read`
- `microsoft.directory/deviceManagementPolicies/basic/update`
- `microsoft.directory/deviceRegistrationPolicy/standard/read`
- `microsoft.directory/deviceRegistrationPolicy/basic/update`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`

---

#### `Compliance Administrator`

- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.directory/entitlementManagement/allProperties/read`
- `microsoft.office365.complianceManager/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Compliance Data Administrator`

- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/cloudAppSecurity/allProperties/allTasks`
- `microsoft.azure.informationProtection/allEntities/allTasks`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.complianceManager/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Conditional Access Administrator`

- `microsoft.directory/conditionalAccessPolicies/create`
- `microsoft.directory/conditionalAccessPolicies/delete`
- `microsoft.directory/conditionalAccessPolicies/standard/read`
- `microsoft.directory/conditionalAccessPolicies/owners/read`
- `microsoft.directory/conditionalAccessPolicies/policyAppliedTo/read`
- `microsoft.directory/conditionalAccessPolicies/basic/update`
- `microsoft.directory/conditionalAccessPolicies/owners/update`
- `microsoft.directory/conditionalAccessPolicies/tenantDefault/update`
- `microsoft.directory/crossTenantAccessPolicies/create`
- `microsoft.directory/crossTenantAccessPolicies/delete`
- `microsoft.directory/crossTenantAccessPolicies/standard/read`
- `microsoft.directory/crossTenantAccessPolicies/owners/read`
- `microsoft.directory/crossTenantAccessPolicies/policyAppliedTo/read`
- `microsoft.directory/crossTenantAccessPolicies/basic/update`
- `microsoft.directory/crossTenantAccessPolicies/owners/update`
- `microsoft.directory/crossTenantAccessPolicies/tenantDefault/update`

---

#### `Customer LockBox Access Approver`

- `microsoft.office365.lockbox/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Desktop Analytics Administrator`

- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.desktopAnalytics/allEntities/allTasks`

---

#### `Device Join`


---

#### `Device Managers`

- `microsoft.directory/devices/standard/read`
- `microsoft.directory/devices/memberOf/read`
- `microsoft.directory/devices/registeredOwners/read`
- `microsoft.directory/devices/registeredUsers/read`
- `microsoft.directory/devices/basic/update`
- `microsoft.directory/devices/extensionAttributeSet1/update`
- `microsoft.directory/devices/extensionAttributeSet2/update`
- `microsoft.directory/devices/extensionAttributeSet3/update`
- `microsoft.directory/devices/registeredOwners/update`
- `microsoft.directory/devices/registeredUsers/update`

---

#### `Device Users`


---

#### `Directory Readers`

- `microsoft.directory/administrativeUnits/standard/read`
- `microsoft.directory/administrativeUnits/members/read`
- `microsoft.directory/applications/standard/read`
- `microsoft.directory/applications/owners/read`
- `microsoft.directory/applications/policies/read`
- `microsoft.directory/contacts/standard/read`
- `microsoft.directory/contacts/memberOf/read`
- `microsoft.directory/contracts/standard/read`
- `microsoft.directory/devices/standard/read`
- `microsoft.directory/devices/memberOf/read`
- `microsoft.directory/devices/registeredOwners/read`
- `microsoft.directory/devices/registeredUsers/read`
- `microsoft.directory/directoryRoles/standard/read`
- `microsoft.directory/directoryRoles/eligibleMembers/read`
- `microsoft.directory/directoryRoles/members/read`
- `microsoft.directory/domains/standard/read`
- `microsoft.directory/groups/standard/read`
- `microsoft.directory/groups/appRoleAssignments/read`
- `microsoft.directory/groups/memberOf/read`
- `microsoft.directory/groups/members/read`
- `microsoft.directory/groups/owners/read`
- `microsoft.directory/groups/settings/read`
- `microsoft.directory/groupSettings/standard/read`
- `microsoft.directory/groupSettingTemplates/standard/read`
- `microsoft.directory/oAuth2PermissionGrants/standard/read`
- `microsoft.directory/organization/standard/read`
- `microsoft.directory/organization/trustedCAsForPasswordlessAuth/read`
- `microsoft.directory/applicationPolicies/standard/read`
- `microsoft.directory/roleAssignments/standard/read`
- `microsoft.directory/roleDefinitions/standard/read`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/read`
- `microsoft.directory/servicePrincipals/appRoleAssignments/read`
- `microsoft.directory/servicePrincipals/standard/read`
- `microsoft.directory/servicePrincipals/memberOf/read`
- `microsoft.directory/servicePrincipals/oAuth2PermissionGrants/read`
- `microsoft.directory/servicePrincipals/owners/read`
- `microsoft.directory/servicePrincipals/ownedObjects/read`
- `microsoft.directory/servicePrincipals/policies/read`
- `microsoft.directory/subscribedSkus/standard/read`
- `microsoft.directory/users/standard/read`
- `microsoft.directory/users/appRoleAssignments/read`
- `microsoft.directory/users/deviceForResourceAccount/read`
- `microsoft.directory/users/directReports/read`
- `microsoft.directory/users/licenseDetails/read`
- `microsoft.directory/users/manager/read`
- `microsoft.directory/users/memberOf/read`
- `microsoft.directory/users/oAuth2PermissionGrants/read`
- `microsoft.directory/users/ownedDevices/read`
- `microsoft.directory/users/ownedObjects/read`
- `microsoft.directory/users/photo/read`
- `microsoft.directory/users/registeredDevices/read`
- `microsoft.directory/users/scopedRoleMemberOf/read`

---

#### `Directory Synchronization Accounts`

- `microsoft.directory/applications/create`
- `microsoft.directory/applications/delete`
- `microsoft.directory/applications/appRoles/update`
- `microsoft.directory/applications/audience/update`
- `microsoft.directory/applications/authentication/update`
- `microsoft.directory/applications/basic/update`
- `microsoft.directory/applications/credentials/update`
- `microsoft.directory/applications/notes/update`
- `microsoft.directory/applications/owners/update`
- `microsoft.directory/applications/permissions/update`
- `microsoft.directory/applications/policies/update`
- `microsoft.directory/applications/tag/update`
- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/hybridAuthenticationPolicy/allProperties/allTasks`
- `microsoft.directory/organization/dirSync/update`
- `microsoft.directory/passwordHashSync/allProperties/allTasks`
- `microsoft.directory/policies/create`
- `microsoft.directory/policies/delete`
- `microsoft.directory/policies/standard/read`
- `microsoft.directory/policies/owners/read`
- `microsoft.directory/policies/policyAppliedTo/read`
- `microsoft.directory/policies/basic/update`
- `microsoft.directory/policies/owners/update`
- `microsoft.directory/policies/tenantDefault/update`
- `microsoft.directory/servicePrincipals/create`
- `microsoft.directory/servicePrincipals/delete`
- `microsoft.directory/servicePrincipals/enable`
- `microsoft.directory/servicePrincipals/disable`
- `microsoft.directory/servicePrincipals/getPasswordSingleSignOnCredentials`
- `microsoft.directory/servicePrincipals/managePasswordSingleSignOnCredentials`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/read`
- `microsoft.directory/servicePrincipals/appRoleAssignments/read`
- `microsoft.directory/servicePrincipals/standard/read`
- `microsoft.directory/servicePrincipals/memberOf/read`
- `microsoft.directory/servicePrincipals/oAuth2PermissionGrants/read`
- `microsoft.directory/servicePrincipals/owners/read`
- `microsoft.directory/servicePrincipals/ownedObjects/read`
- `microsoft.directory/servicePrincipals/policies/read`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`
- `microsoft.directory/servicePrincipals/audience/update`
- `microsoft.directory/servicePrincipals/authentication/update`
- `microsoft.directory/servicePrincipals/basic/update`
- `microsoft.directory/servicePrincipals/credentials/update`
- `microsoft.directory/servicePrincipals/notes/update`
- `microsoft.directory/servicePrincipals/owners/update`
- `microsoft.directory/servicePrincipals/permissions/update`
- `microsoft.directory/servicePrincipals/policies/update`
- `microsoft.directory/servicePrincipals/tag/update`

---

#### `Directory Writers`

- `microsoft.directory/applications/extensionProperties/update`
- `microsoft.directory/groups/assignLicense`
- `microsoft.directory/groups/create`
- `microsoft.directory/groups/reprocessLicenseAssignment`
- `microsoft.directory/groups/basic/update`
- `microsoft.directory/groups/classification/update`
- `microsoft.directory/groups/dynamicMembershipRule/update`
- `microsoft.directory/groups/groupType/update`
- `microsoft.directory/groups/members/update`
- `microsoft.directory/groups/onPremWriteBack/update`
- `microsoft.directory/groups/owners/update`
- `microsoft.directory/groups/settings/update`
- `microsoft.directory/groups/visibility/update`
- `microsoft.directory/groupSettings/create`
- `microsoft.directory/groupSettings/delete`
- `microsoft.directory/groupSettings/basic/update`
- `microsoft.directory/oAuth2PermissionGrants/create`
- `microsoft.directory/oAuth2PermissionGrants/basic/update`
- `microsoft.directory/servicePrincipals/synchronizationCredentials/manage`
- `microsoft.directory/servicePrincipals/synchronizationJobs/manage`
- `microsoft.directory/servicePrincipals/synchronizationSchema/manage`
- `microsoft.directory/servicePrincipals/managePermissionGrantsForGroup.microsoft-all-application-permissions`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`
- `microsoft.directory/users/assignLicense`
- `microsoft.directory/users/create`
- `microsoft.directory/users/disable`
- `microsoft.directory/users/enable`
- `microsoft.directory/users/invalidateAllRefreshTokens`
- `microsoft.directory/users/inviteGuest`
- `microsoft.directory/users/reprocessLicenseAssignment`
- `microsoft.directory/users/basic/update`
- `microsoft.directory/users/manager/update`
- `microsoft.directory/users/photo/update`
- `microsoft.directory/users/userPrincipalName/update`

---

#### `Domain Name Administrator`

- `microsoft.directory/domains/allProperties/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Dynamics 365 Administrator`

- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.dynamics365/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Edge Administrator`

- `microsoft.edge/allEntities/allProperties/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Exchange Administrator`

- `microsoft.directory/groups/hiddenMembers/read`
- `microsoft.directory/groups.unified/create`
- `microsoft.directory/groups.unified/delete`
- `microsoft.directory/groups.unified/restore`
- `microsoft.directory/groups.unified/basic/update`
- `microsoft.directory/groups.unified/members/update`
- `microsoft.directory/groups.unified/owners/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.exchange/allEntities/basic/allTasks`
- `microsoft.office365.network/performance/allProperties/read`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.usageReports/allEntities/allProperties/read`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Exchange Recipient Administrator`

- `microsoft.office365.exchange/allRecipients/allProperties/allTasks`
- `microsoft.office365.exchange/messageTracking/allProperties/allTasks`
- `microsoft.office365.exchange/migration/allProperties/allTasks`

---

#### `External ID User Flow Administrator`

- `microsoft.directory/b2cUserFlow/allProperties/allTasks`

---

#### `External ID User Flow Attribute Administrator`

- `microsoft.directory/b2cUserAttribute/allProperties/allTasks`

---

#### `External Identity Provider Administrator`

- `microsoft.directory/identityProviders/allProperties/allTasks`

---

#### `Global Administrator`

- `microsoft.directory/accessReviews/allProperties/allTasks`
- `microsoft.directory/administrativeUnits/allProperties/allTasks`
- `microsoft.directory/applications/allProperties/allTasks`
- `microsoft.directory/applications/synchronization/standard/read`
- `microsoft.directory/applicationTemplates/instantiate`
- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/users/authenticationMethods/create`
- `microsoft.directory/users/authenticationMethods/delete`
- `microsoft.directory/users/authenticationMethods/standard/read`
- `microsoft.directory/users/authenticationMethods/basic/update`
- `microsoft.directory/authorizationPolicy/allProperties/allTasks`
- `microsoft.directory/bitlockerKeys/key/read`
- `microsoft.directory/cloudAppSecurity/allProperties/allTasks`
- `microsoft.directory/connectors/create`
- `microsoft.directory/connectors/allProperties/read`
- `microsoft.directory/connectorGroups/create`
- `microsoft.directory/connectorGroups/delete`
- `microsoft.directory/connectorGroups/allProperties/read`
- `microsoft.directory/connectorGroups/allProperties/update`
- `microsoft.directory/contacts/allProperties/allTasks`
- `microsoft.directory/contracts/allProperties/allTasks`
- `microsoft.directory/customAuthenticationExtensions/allProperties/allTasks`
- `microsoft.directory/deletedItems/delete`
- `microsoft.directory/deletedItems/restore`
- `microsoft.directory/devices/allProperties/allTasks`
- `microsoft.directory/deviceManagementPolicies/standard/read`
- `microsoft.directory/deviceManagementPolicies/basic/update`
- `microsoft.directory/deviceRegistrationPolicy/standard/read`
- `microsoft.directory/deviceRegistrationPolicy/basic/update`
- `microsoft.directory/directoryRoles/allProperties/allTasks`
- `microsoft.directory/directoryRoleTemplates/allProperties/allTasks`
- `microsoft.directory/domains/allProperties/allTasks`
- `microsoft.directory/entitlementManagement/allProperties/allTasks`
- `microsoft.directory/groups/allProperties/allTasks`
- `microsoft.directory/groupsAssignableToRoles/create`
- `microsoft.directory/groupsAssignableToRoles/delete`
- `microsoft.directory/groupsAssignableToRoles/restore`
- `microsoft.directory/groupsAssignableToRoles/allProperties/update`
- `microsoft.directory/groupSettings/allProperties/allTasks`
- `microsoft.directory/groupSettingTemplates/allProperties/allTasks`
- `microsoft.directory/hybridAuthenticationPolicy/allProperties/allTasks`
- `microsoft.directory/identityProtection/allProperties/allTasks`
- `microsoft.directory/loginOrganizationBranding/allProperties/allTasks`
- `microsoft.directory/oAuth2PermissionGrants/allProperties/allTasks`
- `microsoft.directory/organization/allProperties/allTasks`
- `microsoft.directory/passwordHashSync/allProperties/allTasks`
- `microsoft.directory/policies/allProperties/allTasks`
- `microsoft.directory/conditionalAccessPolicies/allProperties/allTasks`
- `microsoft.directory/crossTenantAccessPolicies/allProperties/allTasks`
- `microsoft.directory/privilegedIdentityManagement/allProperties/read`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/roleAssignments/allProperties/allTasks`
- `microsoft.directory/roleDefinitions/allProperties/allTasks`
- `microsoft.directory/scopedRoleMemberships/allProperties/allTasks`
- `microsoft.directory/serviceAction/activateService`
- `microsoft.directory/serviceAction/disableDirectoryFeature`
- `microsoft.directory/serviceAction/enableDirectoryFeature`
- `microsoft.directory/serviceAction/getAvailableExtentionProperties`
- `microsoft.directory/servicePrincipals/allProperties/allTasks`
- `microsoft.directory/servicePrincipals/managePermissionGrantsForAll.microsoft-company-admin`
- `microsoft.directory/servicePrincipals/managePermissionGrantsForGroup.microsoft-all-application-permissions`
- `microsoft.directory/servicePrincipals/synchronization/standard/read`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.directory/subscribedSkus/allProperties/allTasks`
- `microsoft.directory/users/allProperties/allTasks`
- `microsoft.directory/permissionGrantPolicies/create`
- `microsoft.directory/permissionGrantPolicies/delete`
- `microsoft.directory/permissionGrantPolicies/standard/read`
- `microsoft.directory/permissionGrantPolicies/basic/update`
- `microsoft.directory/servicePrincipalCreationPolicies/create`
- `microsoft.directory/servicePrincipalCreationPolicies/delete`
- `microsoft.directory/servicePrincipalCreationPolicies/standard/read`
- `microsoft.directory/servicePrincipalCreationPolicies/basic/update`
- `microsoft.directory/verifiableCredentials/configuration/contracts/cards/allProperties/read`
- `microsoft.directory/verifiableCredentials/configuration/contracts/cards/revoke`
- `microsoft.directory/verifiableCredentials/configuration/contracts/create`
- `microsoft.directory/verifiableCredentials/configuration/contracts/allProperties/read`
- `microsoft.directory/verifiableCredentials/configuration/contracts/allProperties/update`
- `microsoft.directory/verifiableCredentials/configuration/create`
- `microsoft.directory/verifiableCredentials/configuration/delete`
- `microsoft.directory/verifiableCredentials/configuration/allProperties/read`
- `microsoft.directory/verifiableCredentials/configuration/allProperties/update`
- `microsoft.azure.advancedThreatProtection/allEntities/allTasks`
- `microsoft.azure.informationProtection/allEntities/allTasks`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.cloudPC/allEntities/allProperties/allTasks`
- `microsoft.commerce.billing/allEntities/allTasks`
- `microsoft.dynamics365/allEntities/allTasks`
- `microsoft.edge/allEntities/allProperties/allTasks`
- `microsoft.flow/allEntities/allTasks`
- `microsoft.intune/allEntities/allTasks`
- `microsoft.office365.complianceManager/allEntities/allTasks`
- `microsoft.office365.desktopAnalytics/allEntities/allTasks`
- `microsoft.office365.exchange/allEntities/basic/allTasks`
- `microsoft.office365.knowledge/contentUnderstanding/allProperties/allTasks`
- `microsoft.office365.knowledge/contentUnderstanding/analytics/allProperties/read`
- `microsoft.office365.knowledge/knowledgeNetwork/allProperties/allTasks`
- `microsoft.office365.knowledge/knowledgeNetwork/topicVisibility/allProperties/allTasks`
- `microsoft.office365.knowledge/learningSources/allProperties/allTasks`
- `microsoft.office365.lockbox/allEntities/allTasks`
- `microsoft.office365.messageCenter/messages/read`
- `microsoft.office365.messageCenter/securityMessages/read`
- `microsoft.office365.network/performance/allProperties/read`
- `microsoft.office365.protectionCenter/allEntities/allProperties/allTasks`
- `microsoft.office365.search/content/manage`
- `microsoft.office365.securityComplianceCenter/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.sharePoint/allEntities/allTasks`
- `microsoft.office365.skypeForBusiness/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.usageReports/allEntities/allProperties/read`
- `microsoft.office365.userCommunication/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`
- `microsoft.office365.yammer/allEntities/allProperties/allTasks`
- `microsoft.powerApps/allEntities/allTasks`
- `microsoft.powerApps.powerBI/allEntities/allTasks`
- `microsoft.teams/allEntities/allProperties/allTasks`
- `microsoft.windows.defenderAdvancedThreatProtection/allEntities/allTasks`
- `microsoft.windows.updatesDeployments/allEntities/allProperties/allTasks`

---

#### `Global Reader`

- `microsoft.directory/accessReviews/allProperties/read`
- `microsoft.directory/administrativeUnits/allProperties/read`
- `microsoft.directory/applications/allProperties/read`
- `microsoft.directory/applications/synchronization/standard/read`
- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/users/authenticationMethods/standard/restrictedRead`
- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/bitlockerKeys/key/read`
- `microsoft.directory/cloudAppSecurity/allProperties/read`
- `microsoft.directory/connectors/allProperties/read`
- `microsoft.directory/connectorGroups/allProperties/read`
- `microsoft.directory/contacts/allProperties/read`
- `microsoft.directory/customAuthenticationExtensions/allProperties/read`
- `microsoft.directory/devices/allProperties/read`
- `microsoft.directory/directoryRoles/allProperties/read`
- `microsoft.directory/directoryRoleTemplates/allProperties/read`
- `microsoft.directory/domains/allProperties/read`
- `microsoft.directory/entitlementManagement/allProperties/read`
- `microsoft.directory/groups/allProperties/read`
- `microsoft.directory/groupSettings/allProperties/read`
- `microsoft.directory/groupSettingTemplates/allProperties/read`
- `microsoft.directory/identityProtection/allProperties/read`
- `microsoft.directory/loginOrganizationBranding/allProperties/read`
- `microsoft.directory/oAuth2PermissionGrants/allProperties/read`
- `microsoft.directory/organization/allProperties/read`
- `microsoft.directory/permissionGrantPolicies/standard/read`
- `microsoft.directory/policies/allProperties/read`
- `microsoft.directory/conditionalAccessPolicies/allProperties/read`
- `microsoft.directory/crossTenantAccessPolicies/allProperties/read`
- `microsoft.directory/deviceManagementPolicies/standard/read`
- `microsoft.directory/deviceRegistrationPolicy/standard/read`
- `microsoft.directory/privilegedIdentityManagement/allProperties/read`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/roleAssignments/allProperties/read`
- `microsoft.directory/roleDefinitions/allProperties/read`
- `microsoft.directory/scopedRoleMemberships/allProperties/read`
- `microsoft.directory/serviceAction/getAvailableExtentionProperties`
- `microsoft.directory/servicePrincipals/allProperties/read`
- `microsoft.directory/servicePrincipalCreationPolicies/standard/read`
- `microsoft.directory/servicePrincipals/synchronization/standard/read`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.directory/subscribedSkus/allProperties/read`
- `microsoft.directory/users/allProperties/read`
- `microsoft.directory/verifiableCredentials/configuration/contracts/cards/allProperties/read`
- `microsoft.directory/verifiableCredentials/configuration/contracts/allProperties/read`
- `microsoft.directory/verifiableCredentials/configuration/allProperties/read`
- `microsoft.cloudPC/allEntities/allProperties/read`
- `microsoft.commerce.billing/allEntities/read`
- `microsoft.edge/allEntities/allProperties/read`
- `microsoft.office365.exchange/allEntities/standard/read`
- `microsoft.office365.messageCenter/messages/read`
- `microsoft.office365.messageCenter/securityMessages/read`
- `microsoft.office365.network/performance/allProperties/read`
- `microsoft.office365.protectionCenter/allEntities/allProperties/read`
- `microsoft.office365.securityComplianceCenter/allEntities/read`
- `microsoft.office365.usageReports/allEntities/allProperties/read`
- `microsoft.office365.webPortal/allEntities/standard/read`
- `microsoft.office365.yammer/allEntities/allProperties/read`
- `microsoft.teams/allEntities/allProperties/read`
- `microsoft.windows.updatesDeployments/allEntities/allProperties/read`

---

#### `Groups Administrator`

- `microsoft.directory/deletedItems.groups/delete`
- `microsoft.directory/deletedItems.groups/restore`
- `microsoft.directory/groups/assignLicense`
- `microsoft.directory/groups/create`
- `microsoft.directory/groups/delete`
- `microsoft.directory/groups/hiddenMembers/read`
- `microsoft.directory/groups/reprocessLicenseAssignment`
- `microsoft.directory/groups/restore`
- `microsoft.directory/groups/basic/update`
- `microsoft.directory/groups/classification/update`
- `microsoft.directory/groups/dynamicMembershipRule/update`
- `microsoft.directory/groups/groupType/update`
- `microsoft.directory/groups/members/update`
- `microsoft.directory/groups/onPremWriteBack/update`
- `microsoft.directory/groups/owners/update`
- `microsoft.directory/groups/settings/update`
- `microsoft.directory/groups/visibility/update`
- `microsoft.directory/servicePrincipals/managePermissionGrantsForGroup.microsoft-all-application-permissions`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Guest Inviter`

- `microsoft.directory/users/inviteGuest`
- `microsoft.directory/users/standard/read`
- `microsoft.directory/users/appRoleAssignments/read`
- `microsoft.directory/users/deviceForResourceAccount/read`
- `microsoft.directory/users/directReports/read`
- `microsoft.directory/users/licenseDetails/read`
- `microsoft.directory/users/manager/read`
- `microsoft.directory/users/memberOf/read`
- `microsoft.directory/users/oAuth2PermissionGrants/read`
- `microsoft.directory/users/ownedDevices/read`
- `microsoft.directory/users/ownedObjects/read`
- `microsoft.directory/users/photo/read`
- `microsoft.directory/users/registeredDevices/read`
- `microsoft.directory/users/scopedRoleMemberOf/read`

---

#### `Guest User`

- `microsoft.directory/applications/standard/limitedRead`
- `microsoft.directory/applications/owners/limitedRead`
- `microsoft.directory/applications/policies/limitedRead`
- `microsoft.directory/domains/standard/read`
- `microsoft.directory/groups/standard/limitedRead`
- `microsoft.directory/groups/appRoleAssignments/limitedRead`
- `microsoft.directory/groups/memberOf/limitedRead`
- `microsoft.directory/groups/members/limitedRead`
- `microsoft.directory/groups/owners/limitedRead`
- `microsoft.directory/groups/settings/limitedRead`
- `microsoft.directory/organization/basicProfile/read`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/limitedRead`
- `microsoft.directory/servicePrincipals/appRoleAssignments/limitedRead`
- `microsoft.directory/servicePrincipals/standard/limitedRead`
- `microsoft.directory/servicePrincipals/memberOf/limitedRead`
- `microsoft.directory/servicePrincipals/oAuth2PermissionGrants/limitedRead`
- `microsoft.directory/servicePrincipals/owners/limitedRead`
- `microsoft.directory/servicePrincipals/ownedObjects/limitedRead`
- `microsoft.directory/servicePrincipals/policies/limitedRead`
- `microsoft.directory/users/inviteGuest`
- `microsoft.directory/users/guestBasicProfile/limitedRead`
- `microsoft.directory/users/standard/read`
- `microsoft.directory/users/appRoleAssignments/read`
- `microsoft.directory/users/deviceForResourceAccount/read`
- `microsoft.directory/users/directReports/read`
- `microsoft.directory/users/eligibleMemberOf/read`
- `microsoft.directory/users/licenseDetails/read`
- `microsoft.directory/users/manager/read`
- `microsoft.directory/users/memberOf/read`
- `microsoft.directory/users/oAuth2PermissionGrants/read`
- `microsoft.directory/users/ownedDevices/read`
- `microsoft.directory/users/ownedObjects/read`
- `microsoft.directory/users/pendingMemberOf/read`
- `microsoft.directory/users/photo/read`
- `microsoft.directory/users/registeredDevices/read`
- `microsoft.directory/users/scopedRoleMemberOf/read`
- `microsoft.directory/users/password/update`

---

#### `Helpdesk Administrator`

- `microsoft.directory/bitlockerKeys/key/read`
- `microsoft.directory/users/invalidateAllRefreshTokens`
- `microsoft.directory/users/password/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Hybrid Identity Administrator`

- `microsoft.directory/applications/create`
- `microsoft.directory/applications/delete`
- `microsoft.directory/applications/appRoles/update`
- `microsoft.directory/applications/audience/update`
- `microsoft.directory/applications/authentication/update`
- `microsoft.directory/applications/basic/update`
- `microsoft.directory/applications/notes/update`
- `microsoft.directory/applications/owners/update`
- `microsoft.directory/applications/permissions/update`
- `microsoft.directory/applications/policies/update`
- `microsoft.directory/applications/tag/update`
- `microsoft.directory/applications/synchronization/standard/read`
- `microsoft.directory/applicationTemplates/instantiate`
- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/cloudProvisioning/allProperties/allTasks`
- `microsoft.directory/deletedItems.applications/delete`
- `microsoft.directory/deletedItems.applications/restore`
- `microsoft.directory/domains/allProperties/read`
- `microsoft.directory/domains/federation/update`
- `microsoft.directory/hybridAuthenticationPolicy/allProperties/allTasks`
- `microsoft.directory/organization/dirSync/update`
- `microsoft.directory/passwordHashSync/allProperties/allTasks`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/servicePrincipals/create`
- `microsoft.directory/servicePrincipals/delete`
- `microsoft.directory/servicePrincipals/disable`
- `microsoft.directory/servicePrincipals/enable`
- `microsoft.directory/servicePrincipals/synchronizationCredentials/manage`
- `microsoft.directory/servicePrincipals/synchronizationJobs/manage`
- `microsoft.directory/servicePrincipals/synchronizationSchema/manage`
- `microsoft.directory/servicePrincipals/audience/update`
- `microsoft.directory/servicePrincipals/authentication/update`
- `microsoft.directory/servicePrincipals/basic/update`
- `microsoft.directory/servicePrincipals/notes/update`
- `microsoft.directory/servicePrincipals/owners/update`
- `microsoft.directory/servicePrincipals/permissions/update`
- `microsoft.directory/servicePrincipals/policies/update`
- `microsoft.directory/servicePrincipals/tag/update`
- `microsoft.directory/servicePrincipals/synchronization/standard/read`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.messageCenter/messages/read`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Identity Governance Administrator`

- `microsoft.directory/accessReviews/allProperties/allTasks`
- `microsoft.directory/entitlementManagement/allProperties/allTasks`
- `microsoft.directory/groups/members/update`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`

---

#### `Insights Administrator`

- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.insights/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Insights Business Leader`

- `microsoft.insights/reports/read`
- `microsoft.insights/programs/update`

---

#### `Intune Administrator`

- `microsoft.directory/bitlockerKeys/key/read`
- `microsoft.directory/contacts/create`
- `microsoft.directory/contacts/delete`
- `microsoft.directory/contacts/basic/update`
- `microsoft.directory/devices/create`
- `microsoft.directory/devices/delete`
- `microsoft.directory/devices/disable`
- `microsoft.directory/devices/enable`
- `microsoft.directory/devices/basic/update`
- `microsoft.directory/devices/extensionAttributeSet1/update`
- `microsoft.directory/devices/extensionAttributeSet2/update`
- `microsoft.directory/devices/extensionAttributeSet3/update`
- `microsoft.directory/devices/registeredOwners/update`
- `microsoft.directory/devices/registeredUsers/update`
- `microsoft.directory/deviceManagementPolicies/standard/read`
- `microsoft.directory/deviceRegistrationPolicy/standard/read`
- `microsoft.directory/groups/hiddenMembers/read`
- `microsoft.directory/groups.security/create`
- `microsoft.directory/groups.security/delete`
- `microsoft.directory/groups.security/basic/update`
- `microsoft.directory/groups.security/classification/update`
- `microsoft.directory/groups.security/dynamicMembershipRule/update`
- `microsoft.directory/groups.security/members/update`
- `microsoft.directory/groups.security/owners/update`
- `microsoft.directory/groups.security/visibility/update`
- `microsoft.directory/users/basic/update`
- `microsoft.directory/users/manager/update`
- `microsoft.directory/users/photo/update`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.cloudPC/allEntities/allProperties/allTasks`
- `microsoft.intune/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Kaizala Administrator`

- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Knowledge Administrator`

- `microsoft.directory/groups.security/create`
- `microsoft.directory/groups.security/createAsOwner`
- `microsoft.directory/groups.security/delete`
- `microsoft.directory/groups.security/basic/update`
- `microsoft.directory/groups.security/members/update`
- `microsoft.directory/groups.security/owners/update`
- `microsoft.office365.knowledge/contentUnderstanding/allProperties/allTasks`
- `microsoft.office365.knowledge/knowledgeNetwork/allProperties/allTasks`
- `microsoft.office365.knowledge/learningSources/allProperties/allTasks`
- `microsoft.office365.protectionCenter/sensitivityLabels/allProperties/read`
- `microsoft.office365.sharePoint/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Knowledge Manager`

- `microsoft.directory/groups.security/create`
- `microsoft.directory/groups.security/createAsOwner`
- `microsoft.directory/groups.security/delete`
- `microsoft.directory/groups.security/basic/update`
- `microsoft.directory/groups.security/members/update`
- `microsoft.directory/groups.security/owners/update`
- `microsoft.office365.knowledge/contentUnderstanding/analytics/allProperties/read`
- `microsoft.office365.knowledge/knowledgeNetwork/topicVisibility/allProperties/allTasks`
- `microsoft.office365.sharePoint/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `License Administrator`

- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/groups/assignLicense`
- `microsoft.directory/groups/reprocessLicenseAssignment`
- `microsoft.directory/users/assignLicense`
- `microsoft.directory/users/reprocessLicenseAssignment`
- `microsoft.directory/users/usageLocation/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Message Center Privacy Reader`

- `microsoft.office365.messageCenter/messages/read`
- `microsoft.office365.messageCenter/securityMessages/read`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Message Center Reader`

- `microsoft.office365.messageCenter/messages/read`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Network Administrator`

- `microsoft.office365.network/locations/allProperties/allTasks`
- `microsoft.office365.network/performance/allProperties/read`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Office Apps Administrator`

- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.messageCenter/messages/read`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.userCommunication/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Partner Tier1 Support`

- `microsoft.directory/applications/appRoles/update`
- `microsoft.directory/applications/audience/update`
- `microsoft.directory/applications/authentication/update`
- `microsoft.directory/applications/basic/update`
- `microsoft.directory/applications/credentials/update`
- `microsoft.directory/applications/notes/update`
- `microsoft.directory/applications/owners/update`
- `microsoft.directory/applications/permissions/update`
- `microsoft.directory/applications/policies/update`
- `microsoft.directory/applications/tag/update`
- `microsoft.directory/contacts/create`
- `microsoft.directory/contacts/delete`
- `microsoft.directory/contacts/basic/update`
- `microsoft.directory/deletedItems.groups/restore`
- `microsoft.directory/groups/create`
- `microsoft.directory/groups/delete`
- `microsoft.directory/groups/restore`
- `microsoft.directory/groups/members/update`
- `microsoft.directory/groups/owners/update`
- `microsoft.directory/oAuth2PermissionGrants/allProperties/allTasks`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`
- `microsoft.directory/users/assignLicense`
- `microsoft.directory/users/create`
- `microsoft.directory/users/delete`
- `microsoft.directory/users/disable`
- `microsoft.directory/users/enable`
- `microsoft.directory/users/invalidateAllRefreshTokens`
- `microsoft.directory/users/restore`
- `microsoft.directory/users/basic/update`
- `microsoft.directory/users/manager/update`
- `microsoft.directory/users/password/update`
- `microsoft.directory/users/photo/update`
- `microsoft.directory/users/userPrincipalName/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Partner Tier2 Support`

- `microsoft.directory/applications/appRoles/update`
- `microsoft.directory/applications/audience/update`
- `microsoft.directory/applications/authentication/update`
- `microsoft.directory/applications/basic/update`
- `microsoft.directory/applications/credentials/update`
- `microsoft.directory/applications/notes/update`
- `microsoft.directory/applications/owners/update`
- `microsoft.directory/applications/permissions/update`
- `microsoft.directory/applications/policies/update`
- `microsoft.directory/applications/tag/update`
- `microsoft.directory/contacts/create`
- `microsoft.directory/contacts/delete`
- `microsoft.directory/contacts/basic/update`
- `microsoft.directory/deletedItems.groups/restore`
- `microsoft.directory/domains/allProperties/allTasks`
- `microsoft.directory/groups/create`
- `microsoft.directory/groups/delete`
- `microsoft.directory/groups/restore`
- `microsoft.directory/groups/members/update`
- `microsoft.directory/groups/owners/update`
- `microsoft.directory/oAuth2PermissionGrants/allProperties/allTasks`
- `microsoft.directory/organization/basic/update`
- `microsoft.directory/roleAssignments/allProperties/allTasks`
- `microsoft.directory/roleDefinitions/allProperties/allTasks`
- `microsoft.directory/scopedRoleMemberships/allProperties/allTasks`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`
- `microsoft.directory/subscribedSkus/standard/read`
- `microsoft.directory/users/assignLicense`
- `microsoft.directory/users/create`
- `microsoft.directory/users/delete`
- `microsoft.directory/users/disable`
- `microsoft.directory/users/enable`
- `microsoft.directory/users/invalidateAllRefreshTokens`
- `microsoft.directory/users/restore`
- `microsoft.directory/users/basic/update`
- `microsoft.directory/users/manager/update`
- `microsoft.directory/users/password/update`
- `microsoft.directory/users/photo/update`
- `microsoft.directory/users/userPrincipalName/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Password Administrator`

- `microsoft.directory/users/password/update`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Power BI Administrator`

- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`
- `microsoft.powerApps.powerBI/allEntities/allTasks`

---

#### `Power Platform Administrator`

- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.dynamics365/allEntities/allTasks`
- `microsoft.flow/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`
- `microsoft.powerApps/allEntities/allTasks`

---

#### `Printer Administrator`

- `microsoft.azure.print/allEntities/allProperties/allTasks`

---

#### `Printer Technician`

- `microsoft.azure.print/connectors/allProperties/read`
- `microsoft.azure.print/printers/allProperties/read`
- `microsoft.azure.print/printers/register`
- `microsoft.azure.print/printers/unregister`
- `microsoft.azure.print/printers/basic/update`

---

#### `Privileged Authentication Administrator`

- `microsoft.directory/users/authenticationMethods/create`
- `microsoft.directory/users/authenticationMethods/delete`
- `microsoft.directory/users/authenticationMethods/standard/read`
- `microsoft.directory/users/authenticationMethods/basic/update`
- `microsoft.directory/users/invalidateAllRefreshTokens`
- `microsoft.directory/users/password/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Privileged Role Administrator`

- `microsoft.directory/administrativeUnits/allProperties/allTasks`
- `microsoft.directory/authorizationPolicy/allProperties/allTasks`
- `microsoft.directory/directoryRoles/allProperties/allTasks`
- `microsoft.directory/groupsAssignableToRoles/create`
- `microsoft.directory/groupsAssignableToRoles/delete`
- `microsoft.directory/groupsAssignableToRoles/restore`
- `microsoft.directory/groupsAssignableToRoles/allProperties/update`
- `microsoft.directory/oAuth2PermissionGrants/allProperties/allTasks`
- `microsoft.directory/privilegedIdentityManagement/allProperties/allTasks`
- `microsoft.directory/roleAssignments/allProperties/allTasks`
- `microsoft.directory/roleDefinitions/allProperties/allTasks`
- `microsoft.directory/scopedRoleMemberships/allProperties/allTasks`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`
- `microsoft.directory/servicePrincipals/permissions/update`
- `microsoft.directory/servicePrincipals/managePermissionGrantsForAll.microsoft-company-admin`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Reports Reader`

- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.office365.network/performance/allProperties/read`
- `microsoft.office365.usageReports/allEntities/allProperties/read`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Restricted Guest User`

- `microsoft.directory/applications/standard/limitedRead`
- `microsoft.directory/applications/owners/limitedRead`
- `microsoft.directory/applications/policies/limitedRead`
- `microsoft.directory/domains/standard/read`
- `microsoft.directory/organization/basicProfile/read`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/limitedRead`
- `microsoft.directory/servicePrincipals/appRoleAssignments/limitedRead`
- `microsoft.directory/servicePrincipals/standard/limitedRead`
- `microsoft.directory/servicePrincipals/memberOf/limitedRead`
- `microsoft.directory/servicePrincipals/oAuth2PermissionGrants/limitedRead`
- `microsoft.directory/servicePrincipals/owners/limitedRead`
- `microsoft.directory/servicePrincipals/ownedObjects/limitedRead`
- `microsoft.directory/servicePrincipals/policies/limitedRead`
- `microsoft.directory/users/standard/read`
- `microsoft.directory/users/appRoleAssignments/read`
- `microsoft.directory/users/deviceForResourceAccount/read`
- `microsoft.directory/users/directReports/read`
- `microsoft.directory/users/eligibleMemberOf/read`
- `microsoft.directory/users/licenseDetails/read`
- `microsoft.directory/users/manager/read`
- `microsoft.directory/users/memberOf/read`
- `microsoft.directory/users/oAuth2PermissionGrants/read`
- `microsoft.directory/users/ownedDevices/read`
- `microsoft.directory/users/ownedObjects/read`
- `microsoft.directory/users/pendingMemberOf/read`
- `microsoft.directory/users/photo/read`
- `microsoft.directory/users/registeredDevices/read`
- `microsoft.directory/users/scopedRoleMemberOf/read`
- `microsoft.directory/users/password/update`

---

#### `Search Administrator`

- `microsoft.office365.messageCenter/messages/read`
- `microsoft.office365.search/content/manage`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Search Editor`

- `microsoft.office365.messageCenter/messages/read`
- `microsoft.office365.search/content/manage`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Security Administrator`

- `microsoft.directory/applications/policies/update`
- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/bitlockerKeys/key/read`
- `microsoft.directory/entitlementManagement/allProperties/read`
- `microsoft.directory/hybridAuthenticationPolicy/allProperties/allTasks`
- `microsoft.directory/identityProtection/allProperties/read`
- `microsoft.directory/identityProtection/allProperties/update`
- `microsoft.directory/passwordHashSync/allProperties/allTasks`
- `microsoft.directory/policies/create`
- `microsoft.directory/policies/delete`
- `microsoft.directory/policies/basic/update`
- `microsoft.directory/policies/owners/update`
- `microsoft.directory/policies/tenantDefault/update`
- `microsoft.directory/conditionalAccessPolicies/create`
- `microsoft.directory/conditionalAccessPolicies/delete`
- `microsoft.directory/conditionalAccessPolicies/standard/read`
- `microsoft.directory/conditionalAccessPolicies/owners/read`
- `microsoft.directory/conditionalAccessPolicies/policyAppliedTo/read`
- `microsoft.directory/conditionalAccessPolicies/basic/update`
- `microsoft.directory/conditionalAccessPolicies/owners/update`
- `microsoft.directory/conditionalAccessPolicies/tenantDefault/update`
- `microsoft.directory/crossTenantAccessPolicies/create`
- `microsoft.directory/crossTenantAccessPolicies/delete`
- `microsoft.directory/crossTenantAccessPolicies/standard/read`
- `microsoft.directory/crossTenantAccessPolicies/owners/read`
- `microsoft.directory/crossTenantAccessPolicies/policyAppliedTo/read`
- `microsoft.directory/crossTenantAccessPolicies/basic/update`
- `microsoft.directory/crossTenantAccessPolicies/owners/update`
- `microsoft.directory/crossTenantAccessPolicies/tenantDefault/update`
- `microsoft.directory/privilegedIdentityManagement/allProperties/read`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/servicePrincipals/policies/update`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.protectionCenter/allEntities/standard/read`
- `microsoft.office365.protectionCenter/allEntities/basic/update`
- `microsoft.office365.protectionCenter/attackSimulator/payload/allProperties/allTasks`
- `microsoft.office365.protectionCenter/attackSimulator/reports/allProperties/read`
- `microsoft.office365.protectionCenter/attackSimulator/simulation/allProperties/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Security Operator`

- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/cloudAppSecurity/allProperties/allTasks`
- `microsoft.directory/identityProtection/allProperties/allTasks`
- `microsoft.directory/privilegedIdentityManagement/allProperties/read`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.azure.advancedThreatProtection/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.intune/allEntities/read`
- `microsoft.office365.securityComplianceCenter/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.windows.defenderAdvancedThreatProtection/allEntities/allTasks`

---

#### `Security Reader`

- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/bitlockerKeys/key/read`
- `microsoft.directory/entitlementManagement/allProperties/read`
- `microsoft.directory/identityProtection/allProperties/read`
- `microsoft.directory/policies/standard/read`
- `microsoft.directory/policies/owners/read`
- `microsoft.directory/policies/policyAppliedTo/read`
- `microsoft.directory/conditionalAccessPolicies/standard/read`
- `microsoft.directory/conditionalAccessPolicies/owners/read`
- `microsoft.directory/conditionalAccessPolicies/policyAppliedTo/read`
- `microsoft.directory/privilegedIdentityManagement/allProperties/read`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.office365.protectionCenter/allEntities/standard/read`
- `microsoft.office365.protectionCenter/attackSimulator/payload/allProperties/read`
- `microsoft.office365.protectionCenter/attackSimulator/reports/allProperties/read`
- `microsoft.office365.protectionCenter/attackSimulator/simulation/allProperties/read`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Service Support Administrator`

- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.network/performance/allProperties/read`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `SharePoint Administrator`

- `microsoft.directory/groups.unified/create`
- `microsoft.directory/groups.unified/delete`
- `microsoft.directory/groups.unified/restore`
- `microsoft.directory/groups.unified/basic/update`
- `microsoft.directory/groups.unified/members/update`
- `microsoft.directory/groups.unified/owners/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.network/performance/allProperties/read`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.sharePoint/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.usageReports/allEntities/allProperties/read`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Skype for Business Administrator`

- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.skypeForBusiness/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.usageReports/allEntities/allProperties/read`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Teams Administrator`

- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/groups/hiddenMembers/read`
- `microsoft.directory/groups.unified/create`
- `microsoft.directory/groups.unified/delete`
- `microsoft.directory/groups.unified/restore`
- `microsoft.directory/groups.unified/basic/update`
- `microsoft.directory/groups.unified/members/update`
- `microsoft.directory/groups.unified/owners/update`
- `microsoft.directory/servicePrincipals/managePermissionGrantsForGroup.microsoft-all-application-permissions`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.network/performance/allProperties/read`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.skypeForBusiness/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.usageReports/allEntities/allProperties/read`
- `microsoft.office365.webPortal/allEntities/standard/read`
- `microsoft.teams/allEntities/allProperties/allTasks`

---

#### `Teams Communications Administrator`

- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.skypeForBusiness/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.usageReports/allEntities/allProperties/read`
- `microsoft.office365.webPortal/allEntities/standard/read`
- `microsoft.teams/callQuality/allProperties/read`
- `microsoft.teams/meetings/allProperties/allTasks`
- `microsoft.teams/voice/allProperties/allTasks`

---

#### `Teams Communications Support Engineer`

- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.skypeForBusiness/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`
- `microsoft.teams/callQuality/allProperties/read`

---

#### `Teams Communications Support Specialist`

- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.skypeForBusiness/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`
- `microsoft.teams/callQuality/standard/read`

---

#### `Teams Devices Administrator`

- `microsoft.office365.webPortal/allEntities/standard/read`
- `microsoft.teams/devices/standard/read`

---

#### `Usage Summary Reports Reader`

- `microsoft.office365.network/performance/allProperties/read`
- `microsoft.office365.usageReports/allEntities/standard/read`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `User`

- `microsoft.directory/applications/createAsOwner`
- `microsoft.directory/authorizationPolicy/standard/read`
- `microsoft.directory/groups/createAsOwner`
- `microsoft.directory/policies/standard/read`
- `microsoft.directory/policies/owners/read`
- `microsoft.directory/policies/policyAppliedTo/read`
- `microsoft.directory/applicationPolicies/createAsOwner`
- `microsoft.directory/servicePrincipals/createAsOwner`
- `microsoft.directory/servicePrincipals/authentication/read`
- `microsoft.directory/users/activateServicePlan`
- `microsoft.directory/users/inviteGuest`
- `microsoft.directory/applications/delete`
- `microsoft.directory/applications/appRoles/update`
- `microsoft.directory/applications/audience/update`
- `microsoft.directory/applications/authentication/update`
- `microsoft.directory/applications/basic/update`
- `microsoft.directory/applications/credentials/update`
- `microsoft.directory/applications/extensionProperties/update`
- `microsoft.directory/applications/notes/update`
- `microsoft.directory/applications/owners/update`
- `microsoft.directory/applications/permissions/update`
- `microsoft.directory/applications/policies/update`
- `microsoft.directory/applications/tag/update`
- `microsoft.directory/applications/verification/update`
- `microsoft.directory/auditLogs/allProperties/read`
- `microsoft.directory/deletedItems.applications/delete`
- `microsoft.directory/deletedItems.applications/restore`
- `microsoft.directory/deletedItems.groups/restore`
- `microsoft.directory/devices/disable`
- `microsoft.directory/groups/delete`
- `microsoft.directory/groups/restore`
- `microsoft.directory/groups/basic/update`
- `microsoft.directory/groups/classification/update`
- `microsoft.directory/groups/groupType/update`
- `microsoft.directory/groups/members/update`
- `microsoft.directory/groups/owners/update`
- `microsoft.directory/groups/settings/update`
- `microsoft.directory/groups/visibility/update`
- `microsoft.directory/groupsAssignableToRoles/delete`
- `microsoft.directory/groupsAssignableToRoles/restore`
- `microsoft.directory/groupsAssignableToRoles/allProperties/update`
- `microsoft.directory/policies/delete`
- `microsoft.directory/policies/basic/update`
- `microsoft.directory/policies/owners/update`
- `microsoft.directory/provisioningLogs/allProperties/read`
- `microsoft.directory/servicePrincipals/delete`
- `microsoft.directory/servicePrincipals/disable`
- `microsoft.directory/servicePrincipals/enable`
- `microsoft.directory/servicePrincipals/getPasswordSingleSignOnCredentials`
- `microsoft.directory/servicePrincipals/managePasswordSingleSignOnCredentials`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`
- `microsoft.directory/servicePrincipals/audience/update`
- `microsoft.directory/servicePrincipals/authentication/update`
- `microsoft.directory/servicePrincipals/basic/update`
- `microsoft.directory/servicePrincipals/credentials/update`
- `microsoft.directory/servicePrincipals/notes/update`
- `microsoft.directory/servicePrincipals/owners/update`
- `microsoft.directory/servicePrincipals/permissions/update`
- `microsoft.directory/servicePrincipals/policies/update`
- `microsoft.directory/servicePrincipals/tag/update`
- `microsoft.directory/signInReports/allProperties/read`
- `microsoft.directory/users/changePassword`
- `microsoft.directory/users/invalidateAllRefreshTokens`
- `microsoft.directory/users/basicProfile/update`
- `microsoft.directory/users/identities/update`
- `microsoft.directory/users/mobile/update`
- `microsoft.directory/users/searchableDeviceKey/update`
- `microsoft.directory/userInfos/address/read`
- `microsoft.directory/userInfos/email/read`
- `microsoft.directory/userInfos/openId/read`
- `microsoft.directory/userInfos/phone/read`
- `microsoft.directory/userInfos/profile/read`

---

#### `User Administrator`

- `microsoft.directory/contacts/create`
- `microsoft.directory/contacts/delete`
- `microsoft.directory/contacts/basic/update`
- `microsoft.directory/deletedItems.groups/restore`
- `microsoft.directory/entitlementManagement/allProperties/allTasks`
- `microsoft.directory/groups/assignLicense`
- `microsoft.directory/groups/create`
- `microsoft.directory/groups/delete`
- `microsoft.directory/groups/hiddenMembers/read`
- `microsoft.directory/groups/reprocessLicenseAssignment`
- `microsoft.directory/groups/restore`
- `microsoft.directory/groups/basic/update`
- `microsoft.directory/groups/classification/update`
- `microsoft.directory/groups/dynamicMembershipRule/update`
- `microsoft.directory/groups/groupType/update`
- `microsoft.directory/groups/members/update`
- `microsoft.directory/groups/onPremWriteBack/update`
- `microsoft.directory/groups/owners/update`
- `microsoft.directory/groups/settings/update`
- `microsoft.directory/groups/visibility/update`
- `microsoft.directory/oAuth2PermissionGrants/allProperties/allTasks`
- `microsoft.directory/policies/standard/read`
- `microsoft.directory/servicePrincipals/appRoleAssignedTo/update`
- `microsoft.directory/users/assignLicense`
- `microsoft.directory/users/create`
- `microsoft.directory/users/delete`
- `microsoft.directory/users/disable`
- `microsoft.directory/users/enable`
- `microsoft.directory/users/inviteGuest`
- `microsoft.directory/users/invalidateAllRefreshTokens`
- `microsoft.directory/users/reprocessLicenseAssignment`
- `microsoft.directory/users/restore`
- `microsoft.directory/users/basic/update`
- `microsoft.directory/users/manager/update`
- `microsoft.directory/users/password/update`
- `microsoft.directory/users/photo/update`
- `microsoft.directory/users/userPrincipalName/update`
- `microsoft.azure.serviceHealth/allEntities/allTasks`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.office365.serviceHealth/allEntities/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Windows 365 Administrator`

- `microsoft.directory/devices/create`
- `microsoft.directory/devices/delete`
- `microsoft.directory/devices/disable`
- `microsoft.directory/devices/enable`
- `microsoft.directory/devices/basic/update`
- `microsoft.directory/devices/extensionAttributeSet1/update`
- `microsoft.directory/devices/extensionAttributeSet2/update`
- `microsoft.directory/devices/extensionAttributeSet3/update`
- `microsoft.directory/devices/registeredOwners/update`
- `microsoft.directory/devices/registeredUsers/update`
- `microsoft.directory/groups.security/create`
- `microsoft.directory/groups.security/delete`
- `microsoft.directory/groups.security/basic/update`
- `microsoft.directory/groups.security/classification/update`
- `microsoft.directory/groups.security/dynamicMembershipRule/update`
- `microsoft.directory/groups.security/members/update`
- `microsoft.directory/groups.security/owners/update`
- `microsoft.directory/groups.security/visibility/update`
- `microsoft.directory/deviceManagementPolicies/standard/read`
- `microsoft.directory/deviceRegistrationPolicy/standard/read`
- `microsoft.azure.supportTickets/allEntities/allTasks`
- `microsoft.cloudPC/allEntities/allProperties/allTasks`
- `microsoft.office365.supportTickets/allEntities/allTasks`
- `microsoft.office365.usageReports/allEntities/allProperties/read`
- `microsoft.office365.webPortal/allEntities/standard/read`

---

#### `Windows Update Deployment Administrator`

- `microsoft.windows.updatesDeployments/allEntities/allProperties/allTasks`

---

#### `Workplace Device Join`


