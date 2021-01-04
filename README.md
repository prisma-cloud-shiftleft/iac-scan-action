# Prisma Cloud IaC Scan Action

## Description

A GitHub Action which runs the Prisma Cloud IaC Scan on the Infrastructure as Code files present in the repository to check for security issues. The action can be configured to report the result as an issue, pull request comment and pull request check, or can be viewed on the pipeline annotations.

## Setup

#### Step 1: Acquire Prisma Cloud API credentials

In order to run the scan the action needs the Prisma Cloud Access Key and Secret Key.

If you do not have a key, refer to [Create and Manage Access Keys](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/manage-prisma-cloud-administrators/create-access-keys.html) to acquire one.

#### Step 2: Create GitHub secrets from the API credentials

Create two GitHub Secrets called "PRISMA_CLOUD_ACCESS_KEY" and "PRISMA_CLOUD_SECRET_KEY" for the Access Key and Secret Key respectively with the values acquired in Step 1.

Refer to [Encrypted secrets](https://docs.github.com/en/free-pro-team@latest/actions/reference/encrypted-secrets) for more details on how to setup secrets.

#### Step 3: Configure Workflow

Configure your workflow based on the following example.

Note: `actions/checkout` step is required to be run before the scan action, otherwise the action does not have access to the CFT files to be scanned.

```yaml
name: Prisma Cloud IaC Scan Example
on: [ pull_request ]

jobs:
  prisma_cloud_iac_scan:
    runs-on: ubuntu-latest
    name: Run Prisma Cloud IaC Scan to check 
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Run Scan on CFT files in the repository
        uses: prisma-cloud-shiftleft/iac-scan-action@v1
        id: iac-scan
        with:
          prisma_api_url: 'https://api.prismacloud.io'
          access_key: ${{ secrets.PRISMA_CLOUD_ACCESS_KEY }}
          secret_key: ${{ secrets.PRISMA_CLOUD_SECRET_KEY }}
          asset_name: 'my-asset-name'
          template_type: 'TF'
          template_version: '0.13'
      - name: Upload scan result artifact
        uses: actions/upload-artifact@v2
        if: success() || failure()
        with:
          name: iac_scan_result
          path: ${{ steps.iac-scan.outputs.iac_scan_result_path }}
```

## Configuration Options

#### Scan options

| Config Key                                                             | Description |
| ---------------------------------------------------------------------- | ----------- |
| prisma_api_url<br />*Required*                                         | The URL for Prisma Cloud varies depending on the region and cluster on which your tenant is deployed.<br />The tenant provisioned for you is, for example, https://app2.prismacloud.io or https://app.eu.prismacloud.io.<br />Replace **app** in the URL with **api** and enter it here. Refer to the [Prisma Cloud REST API Reference](https://api.docs.prismacloud.io/reference#try-the-apis) for more details. |
| access_key<br />*Required*                                             | The access key enables programmatic access.<br />If you do not have a key, refer to [Create and Manage Access Keys](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/manage-prisma-cloud-administrators/create-access-keys.html) to acquire one.<br />We recommend the actual value to be stored as a GitHub Secret and used here in the Action with `${{ secrets.PRISMA_CLOUD_ACCESS_KEY }}` |
| secret_key<br />*Required*                                             | The secret key is provided to you at the time of Access Key generation.<br />You cannot acquire it post generation.<br />We recommend the actual value to be stored as a GitHub Secret and used here in the Action with `${{ secrets.PRISMA_CLOUD_SECRET_KEY }}` |
| asset_name<br />*Required*                                             | Can be a project name or any identifier you want to attach to the scan.<br />Some examples are a CI/CD project name or a Git repository name.<br />Eg: `'my-repo-name'` |
| template_type<br />*Required*                                          | Specify the template type.<br />Valid values are as follows:<br />`'TF'` for Terraform<br />`'CFT'` for AWS CloudFormation<br />`'K8S'` for Kubernetes |
| template_version                                                       | Specify the template version.<br />Valid values are: `'0.11'`, `'0.12'` and `'0.13'`<br />Note: Only used for 'TF' templateType. |
| tags                                                                   | Prisma Cloud tags are different from cloud tags that you might have included in your IaC templates.<br />Prisma Cloud tags will facilitate use of upcoming Prisma Cloud features like role-based access control and policy selection.<br />Eg: `'owner:johndoe,team:creditapp,env:dev'` |
| failure_criteria<br />Default: `'High:1,Medium:1,Low:1,Operator:or'`   | Enables you to evaluate scan results against set failure criteria to obtain failed or passed verdicts. You can set the count for high, medium, and low severity issues and use 'and'/'or' operators to refine your criteria.<br />The IaC scan API checks each severity violation number separately against scan results and applies the operator to each evaluation.<br />The scan triggers a failure if the number of violations is greater than or equal to the failureCriteria values.<br />The Pipeline will be set the Failed if the failure criteria matches. |
| scan_path<br />Default: `'./'`                                         | Path of the directory containing the IaC files.<br />The path is relative to the repository root. |
| variables                                                              | Template variables in comma separate key:value pairs.<br />Eg: `'k1:v1,k2:v2'` |
| variable_files                                                         | Comma separated list of variable file paths.<br />Paths are relative to the repository root.<br />Eg: `'./var1.json,./var2.json'` |
| create_issue<br />Default: `'false'`                                   | If turned on an Issue will be created with the scan report.<br />Note: Only created on scan failure. |
| create_pull_request_check<br />Default: `'false'`                      | If turned on a Check on Pull Request will be created with the scan report. |
| create_pull_request_comment<br />Default: `'false'`                    | If turned on a Comment on the Pull Request will be created with the scan report. |
| github_token<br />Default: `${{ github.token }}`<br />Required if any of the above `create*` are turned on | The GitHub Token.<br />You can choose to use a different token than the pipeline default `GITHUB_TOKEN`.<br />Eg: `${{ secrets.GITHUB_TOKEN }}` |
| result_path<br />Default: `'./prismacloud_iac'`                        | Path for the directory where result files should be written |
| ignore_ssl<br />Default: `'false'`                                     | Should internal API client ignore SSL errors.<br />Useful when using on GitHub Enterprise On-Prem. |

#### Scan outputs

##### Step outputs
| Config Key                      | Description |
| ------------------------------- | ----------- |
| iac_scan_result                 | Overall result of the scan.<br />Can be one of:<br />  1. passed - When either no issues were found or the Failure Criteria threshold was not reached<br />  2. failed - When issues were found and the Failure Criteria threshold for was reached<br />  3. error - When there was a scan execution error, generally due to misconfiguration or invalid templates |
| iac_scan_result_summary         | Summary describing the result of the scan   |
| iac_scan_result_path            | Path for the directory where result files are be written |
| iac_scan_result_issues_csv_path | Path for the detailed Issue result CSV file |
| iac_scan_result_errors_csv_path | Path for the detailed Error result CSV file |
| iac_scan_result_sarif_path      | Path for the detailed result SARIF Log file |
| iac_scan_result_md_path         | Path for the detailed result Markdown file  |

##### Files written to workspace

All paths are relative the workspace root. The base path `./prismacloud_iac` is configurable via `result_path` option.

| File                           | Description                     |
| ------------------------------ | ------------------------------- |
| ./prismacloud_iac/issues.csv   | Scan Issue report in CSV format |
| ./prismacloud_iac/errors.csv   | Scan Error report in CSV format |
| ./prismacloud_iac/result.md    | Scan report in Markdown format  |
| ./prismacloud_iac/result.sarif | Scan report in SARIF Log format |

#### SARIF upload

When scan finds issues the action will always write the report in SARIF Log format in the workspace.

```yaml
name: Prisma Cloud IaC Scan Example
on: [ pull_request ]

jobs:
  prisma_cloud_iac_scan:
    runs-on: ubuntu-latest
    name: Run Prisma Cloud IaC Scan to check 
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Run Scan on CFT files in the repository
        uses: prisma-cloud-shiftleft/iac-scan-action@v1
        id: iac-scan
        with:
          prisma_api_url: 'https://api.prismacloud.io'
          access_key: ${{ secrets.PRISMA_CLOUD_ACCESS_KEY }}
          secret_key: ${{ secrets.PRISMA_CLOUD_SECRET_KEY }}
          asset_name: 'my-asset-name'
          template_type: 'CFT'
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v1
        if: success() || failure()
        with:
          sarif_file: ${{ steps.iac-scan.outputs.iac_scan_result_sarif_path }}
```
