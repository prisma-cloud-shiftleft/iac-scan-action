const fs = require('fs');
const { env } = require('process');
const core = require('@actions/core');
const github = require('@actions/github');
const httpclient = require('@actions/http-client');
const jwt_decode = require('jwt-decode');
const { zip } = require('zip-a-folder');
const yaml = require('js-yaml');
const mdtable = require('markdown-table');
const createCsvWriter = require('csv-writer').createArrayCsvWriter;

const JSON_API_CONTENT_TYPE = 'application/vnd.api+json'
const USER_AGENT = 'IaC Scan GitHub Action/1.0.0'
const SORT_ORDER = ['High', 'Medium', 'Low']
const SUPPORTED_TEMPLATE_TYPES = ['TF', 'tf', 'CFT', 'cft', 'K8S', 'k8s']

run();

async function run() {
  return await core.group('Prisma Cloud IaC Scan', async () => {
    return initAndScan();
  });
}

async function initAndScan() {
  try {
    const startTime = new Date();

    const createIssue = core.getInput('create_issue', { required: true }) == 'true'
    const createPrCheck = core.getInput('create_pull_request_check', { required: true }) == 'true'
    const createPrComment = core.getInput('create_pull_request_comment', { required: true }) == 'true'

    let githubToken = core.getInput('github_token')
    const tokenMissing = (typeof githubToken === 'undefined' || githubToken == null || githubToken.length < 1)

    if ((createIssue || createPrCheck || createPrComment) && tokenMissing) {
      throw 'Input required and not supplied: github_token'
    }

    let rawApiUrl = core.getInput('prisma_api_url', { required: true });
    if (!rawApiUrl.startsWith('https://')) {
      throw 'Invalid API URL: ' + rawApiUrl;
    }
    while (rawApiUrl.endsWith('/')) {
      rawApiUrl = rawApiUrl.substring(0, apiUrl.length - 1);
    }
    const apiUrl = rawApiUrl;

    const accessKey = core.getInput('access_key', { required: true });
    const secretKey = core.getInput('secret_key', { required: true });
    core.setSecret(secretKey);
    const assetName = core.getInput('asset_name', { required: true });
    const templateType = core.getInput('template_type', { required: true });
    const templateVersion = core.getInput('template_version', { required: false });
    const tags = core.getInput('tags');
    const failureCriteriaInput = core.getInput('failure_criteria');
    const variablesInput = core.getInput('variables');
    const variableFilesInput = core.getInput('variable_files');
    const useScanPathWhenPr = core.getInput('use_scan_path_when_pr') == 'true'
    const uploadScanPathOnly = core.getInput('upload_scan_path_only') == 'true'
    let workspaceDir = github.context.workspace
    if (typeof workspaceDir === 'undefined' || workspaceDir == null) {
      workspaceDir = env.GITHUB_WORKSPACE
    }
    while (workspaceDir.endsWith('/')) {
      workspaceDir = workspaceDir.substring(0, workspaceDir.length - 1);
    }
    let repository = github.context.repo;
    let owner = repository.owner;
    let repo = repository.repo;
    let scanPath = core.getInput('scan_path');
    if (scanPath.startsWith('./')) {
      scanPath = scanPath.substring(2);
    } else if (scanPath.startsWith('/')) {
      scanPath = scanPath.substring(1);
    }
    let checkoutPath = workspaceDir
    if (!workspaceDir.endsWith(repo)) {
      checkoutPath = workspaceDir + '/' + repo
    }
    if (!fs.existsSync(checkoutPath + '/' + scanPath)) {
      throw "No file found at provided scan_path '" + scanPath + "'";
    }
    let uploadPath = checkoutPath
    if (uploadScanPathOnly) {
      uploadPath = checkoutPath + '/' + scanPath
      scanPath = ''
    }

    let resultDir = core.getInput('result_path');
    if (resultDir.startsWith('./')) {
      resultDir = resultDir.substring(2);
    } else if (resultDir.startsWith('/')) {
      resultDir = resultDir.substring(1);
    }
    if (resultDir.endsWith('/')) {
      resultDir = resultDir.substring(0, resultDir.length - 1);
    }
    resultDir = workspaceDir + '/' + resultDir;
    // create result directory
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }
    const ignoreSsl = core.getInput('ignore_ssl', { required: true }) == 'true'

    if (SUPPORTED_TEMPLATE_TYPES.indexOf(templateType) < 0) {
      throw "Invalid template_type. Found: '" + templateType + "'. Expected: one of 'TF', 'CFT', 'K8S' ]";
    }

    const failureCriteria = {
      high: 1,
      medium: 1,
      low: 1,
      operator: 'or'
    };
    if (typeof failureCriteriaInput !== 'undefined' && failureCriteriaInput != null) {
      let fcparts = failureCriteriaInput.split(',');
      for (let i = 0; i < fcparts.length; i++) {
        let kvparts = fcparts[i].split(':');
        if (kvparts[0].toLowerCase() == 'high') {
          failureCriteria.high = Number(kvparts[1]);
        } else if (kvparts[0].toLowerCase() == 'medium') {
          failureCriteria.medium = Number(kvparts[1]);
        } else if (kvparts[0].toLowerCase() == 'low') {
          failureCriteria.low = Number(kvparts[1]);
        } else if (kvparts[0].toLowerCase() == 'operator') {
          failureCriteria.operator = kvparts[1].toLowerCase();
        }
      }
    }
    const variables = {}
    if (typeof variablesInput !== 'undefined' && variablesInput != null && variablesInput.length > 0) {
      let varparts = variablesInput.split(',');
      for (let i = 0; i < varparts.length; i++) {
        let kvparts = varparts[i].split(':');
        variables[kvparts[0]] = kvparts[1];
      }
    }
    const variableFiles = []
    if (typeof variableFilesInput !== 'undefined' && variableFilesInput != null && variableFilesInput.length > 0) {
      let varparts = variableFilesInput.split(',');
      for (let i = 0; i < varparts.length; i++) {
        variableFiles.push(varparts[i]);
      }
    }
    core.info('Finished reading configuration');

    const is_pr = (github.context.payload.pull_request && github.context.payload.pull_request.state == 'open');

    const octokit = !tokenMissing
      ? github.getOctokit(githubToken, { userAgent: USER_AGENT, baseUrl: process.env.GITHUB_API_URL })
      : null;

    const scanCtx = {
      startTime: startTime,
      createIssue: createIssue,
      createPrCheck: createPrCheck,
      createPrComment: createPrComment,
      tokenMissing: tokenMissing,
      octokit: octokit,
      assetName: assetName,
      failureCriteria: failureCriteria,
      pcsBaseUrl: apiUrl,
      pcsAccessKey: accessKey,
      pcsSecretKey: secretKey,
      owner: owner,
      repo: repo,
      is_pr: is_pr,
      prNumber: is_pr ? github.context.issue.number : null,
      userId: github.context.actor,
      scanParams: {
        templateType: templateType,
        templateVersion: templateVersion,
        variables: variables,
        variableFiles: variableFiles,
        folders: [scanPath]
      },
      tags: tags,
      workspaceDir: workspaceDir,
      resultDir: resultDir,
      checkoutPath: checkoutPath,
      uploadPath: uploadPath,
      zipName: 'scan-input.zip'
    }

    // get modified files 
    if (is_pr && !useScanPathWhenPr) {
      if (tokenMissing) {
        core.warning('Without githubToken scan cannot be restricted to Pull Request changed files')
      } else {
        const files = await octokit.pulls.listFiles({
          pull_number: github.context.issue.number,
          owner: owner,
          repo: repo
        });
        if (files.data) {
          scanCtx.scanParams.files = files.data.map(function (d) { return d.filename })
        }
      }
    }

    const http = new httpclient.HttpClient(USER_AGENT, [], { ignoreSslError: ignoreSsl });
    scanCtx.http = http;
    const scanResult = await scan(scanCtx);
    if (scanResult.failed) {
      const errorsMsg = await generateError(scanCtx, scanResult.errors)
      const mdPath = scanCtx.resultDir + '/result.md';
      const csvPath = scanCtx.resultDir + '/errors.csv';
      fs.writeFileSync(mdPath, scanCtx.errorMd);
      core.setOutput('iac_scan_result', 'error');
      core.setOutput('iac_scan_result_path', scanCtx.resultDir);
      core.setOutput('iac_scan_result_error_csv_path', csvPath);
      core.setOutput('iac_scan_result_md_path', mdPath);
      core.error(errorsMsg);
      core.setFailed('Prisma Cloud IaC Scan - Please check result artifact for details.');
      core.setOutput('iac_scan_result_summary', errorsMsg);
      if (!tokenMissing) {
        if (is_pr && createPrCheck) {
          const prCheck = await createPullRequestCheck(octokit, owner, repo, 'error', 0, errorsMd)
          core.info('Created check on pull requect: ' + prCheck.data.url)
        }
        if (is_pr && createPrComment) {
          const prComment = await createPullRequestComment(octokit, owner, repo, errorsMd)
          core.info('Created comment on pull requect: ' + prComment.data.url)
        }
        if (createIssue) {
          const issue = await createGhIssue(octokit, owner, repo, is_pr ? github.context.actor : owner, is_pr, 'error', 0, errorsMd)
          core.info('Created Issue: ' + issue.data.url)
        }
      }
    }
  } catch (error) {
    core.setFailed('Prisma Cloud IaC Scan - Error occured while scanning: ' + (error instanceof Error ? error.toString() : error));
  }
}

async function scan(scanCtx) {
  core.info('Creating zip file in: ' + scanCtx.checkoutPath)
  await zip(scanCtx.uploadPath, scanCtx.zipName)

  core.info('Starting scan...')
  const scanInitResult = await initScan(scanCtx)
  if (scanInitResult.failed) {
    return scanInitResult
  }

  const initResult = scanInitResult.result
  core.info('Scan initiated. ScanID: ' + initResult.scanId)

  core.info('Uploading zip...')
  const uploadResult = await uploadFile(scanCtx.http, initResult.s3Url, scanCtx.zipName)
  if (uploadResult.failed) {
    return uploadResult
  }
  core.info('Uploaded zip')
  fs.unlinkSync(scanCtx.zipName)
  core.info('Deleted zip file')

  const triggerResult = await triggerScan(scanCtx, initResult)
  if (triggerResult.failed) {
    return triggerResult
  }
  core.info('Scan start triggered')

  core.info('Start checking for status')
  const statusResult = await awaitScanCompletion(scanCtx, initResult.scanId)
  if (statusResult.failed) {
    return statusResult
  }

  core.info('Scan complete. Fetching result...')

  const scanResult = await getResult(scanCtx, initResult.scanId)
  if (scanResult.failed) {
    return scanResult
  }

  if (statusResult.result.scanStatus != 'error') {
    core.info('Fetching SARIF result...')
    const sarifResult = await getSarifResult(scanCtx, initResult.scanId)
    if (sarifResult.failed) {
      return sarifResult
    }
    const sarifPath = scanCtx.resultDir + '/result.sarif';
    fs.writeFileSync(sarifPath, JSON.stringify(sarifResult.result))
    core.setOutput('iac_scan_result_sarif_path', sarifPath)
    core.info('SARIF Log available at: ' + sarifPath)
  }

  await generateOutput(scanCtx, statusResult.result.scanStatus, scanResult.result)

  return { failed: false }
}

async function getOrRefreshPcsToken(scanCtx) {
  let shouldGetToken = false
  if (scanCtx.pcsTokenExpiry) {
    const now = new Date()
    if (scanCtx.pcsTokenExpiry <= Math.round(now.getTime() / 1000)) {
      shouldGetToken = true
    }
  } else {
    shouldGetToken = true
  }
  if (shouldGetToken) {
    core.info('Authenticating with: URL(' + scanCtx.pcsBaseUrl + ') AccessKey(' + scanCtx.pcsAccessKey + ")")
    const tokenResult = await getAuthenticationToken(scanCtx.http, scanCtx.pcsBaseUrl, scanCtx.pcsAccessKey, scanCtx.pcsSecretKey)
    if (tokenResult.failed) {
      return tokenResult
    }

    const token = jwt_decode(tokenResult.result)
    scanCtx.pcsTokenExpiry = token.exp
    scanCtx.pcsToken = tokenResult.result
  }
  return {
    result: scanCtx.pcsToken,
    failed: false,
    error: null
  }
}

async function getAuthenticationToken(http, pcsBaseUrl, accessKey, secretKey) {
  try {
    const response = await http.postJson(
      pcsBaseUrl + '/login',
      { username: accessKey, password: secretKey }
    );
    if (response.result.token) {
      return {
        result: response.result.token,
        failed: false,
        error: null
      }
    } else {
      return {
        result: null,
        failed: true,
        errors: [{
          status: 'Bad Configuration',
          message: 'Invalid credentials, please verify Action configuration'
        }]
      }
    }
  } catch (error) {
    core.error('error: ' + JSON.stringify(error, null, 2))
    let errors
    // case Host is empty
    if (error.message === 'Error: Invalid URI "/login"') {
      errors = {
        status: 'Bad Configuration',
        message: 'Invalid Prisma Cloud API URL, please verify Action configuration'
      }
    } else if (error.statusCode === 400 || error.statusCode === 401) {
      errors = {
        status: 'Bad Configuration',
        message: 'Invalid credentials, please verify Action configuration'
      }
    } else if (error.name === 'RequestError') {
      errors = {
        status: 'Bad Configuration',
        message: 'Invalid Prisma Cloud API URL, please verify Action configuration'
      }
    } else {
      errors = {
        status: 'Internal Error',
        message: 'Oops! Something went wrong, please try again or refer to documentation'
      }
    }
    return {
      result: null,
      failed: true,
      errors: [errors]
    }
  }
}

async function initScan(scanCtx) {
  const scanAttributes = {
    'org': scanCtx.owner,
    'repository': scanCtx.repo,
    'triggeredOn': github.context.eventName,
    'userId': scanCtx.userId
  }
  if (scanCtx.is_pr) {
    scanAttributes['pullRequestId'] = scanCtx.prNumber
    scanAttributes['branch'] = github.context.payload.pull_request.head_ref
  } else {
    scanAttributes['branch'] = github.context.ref
  }

  const tags = await getTags(scanCtx);
  const initReqBody = {
    'data': {
      'type': 'async-scan',
      'attributes': {
        'assetName': scanCtx.assetName,
        'assetType': 'GitHub',
        'tags': tags,
        'scanAttributes': scanAttributes,
        'failureCriteria': scanCtx.failureCriteria
      }
    }
  }

  let tokenResult = await getOrRefreshPcsToken(scanCtx)
  if (tokenResult.failed) {
    return tokenResult
  }

  try {
    const response = await scanCtx.http.postJson(
      scanCtx.pcsBaseUrl + '/iac/v2/scans',
      initReqBody,
      {
        'x-redlock-auth': tokenResult.result,
        'content-type': JSON_API_CONTENT_TYPE,
        'accept': JSON_API_CONTENT_TYPE
      }
    );
    if (response.result.errors) {
      return {
        result: null,
        failed: true,
        errors: response.result.errors.map(function (e) {
          return {
            status: e.status,
            message: e.detail
          }
        })
      }
    }
    const result = {
      scanId: response.result.data.id,
      s3Url: response.result.data.links.url
    }
    return {
      result: result,
      failed: false,
      errors: null
    }
  } catch (error) {
    core.error('error : ' + JSON.stringify(error, null, 2));
    if (typeof error.result === 'undefined' || error.result == null
      || typeof error.result.errors === 'undefined' || error.result.errors == null) {
      let message = error.name
      if (typeof error.statusCode !== 'undefined' && error.statusCode != null) {
        message = message + ' : ' + error.statusCode;
      }
      return {
        result: null,
        failed: true,
        errors: [{
          status: 'Internal Error',
          message: message
        }]
      }
    }
    const responseBody = error.result
    let errors = []
    if (responseBody.errors) {
      errors = responseBody.errors.map(function (e) {
        return {
          status: e.status,
          message: e.detail
        }
      })
    } else {
      errors = [{
        status: 'Internal Error',
        message: error.error
      }]
    }
    return {
      result: null,
      failed: true,
      errors: errors
    }
  }
}

async function uploadFile(http, s3Url, zipName) {
  try {
    const zipFileStats = fs.statSync(zipName);
    const response = await http.sendStream(
      'PUT', s3Url,
      fs.createReadStream(zipName),
      {
        'content-type': 'application/octet-stream',
        'content-length': zipFileStats.size
      }
    )
    return {
      result: null,
      failed: false,
      errors: null
    }
  } catch (error) {
    core.error('error : ' + JSON.stringify(error, null, 2));
    return {
      result: null,
      failed: true,
      errors: [{
        status: 'File Upload Error',
        message: "Failed to upload file to S3. Error: '" + error.name + "'. Status Code: " + error.statusCode
      }]
    }
  }
}

async function triggerScan(scanCtx, initResult) {
  let vars = {};
  let varFiles = [];

  if (typeof scanCtx.configYml !== 'undefined' && scanCtx.configYml != null
    && scanCtx.configYml.template_parameters !== 'undefined'
    && scanCtx.configYml.template_parameters != null) {
    const configVars = scanCtx.configYml.template_parameters.variables;
    const configVarFiles = scanCtx.configYml.template_parameters.variableFiles;
    if (typeof configVars !== 'undefined' && configVars != null && Object.keys(configVars).length > 0) {
      vars = configVars;
    }
    if (typeof configVarFiles !== 'undefined' && configVarFiles != null && configVarFiles.length > 0) {
      varFiles = configVarFiles;
    }
  }

  const inputVars = scanCtx.scanParams.variables
  const inputVarFiles = scanCtx.scanParams.variableFiles
  if (typeof inputVars !== 'undefined' && inputVars != null && Object.keys(inputVars).length > 0) {
    vars = inputVars;
  }
  if (typeof inputVarFiles !== 'undefined' && inputVarFiles != null && inputVarFiles.length > 0) {
    varFiles = inputVarFiles;
  }

  let triggerRequest = {
    'data': {
      'id': initResult.scanId,
      'attributes': {
        'templateType': scanCtx.scanParams.templateType,
        'templateVersion': scanCtx.scanParams.templateVersion,
        'templateParameters': {
          'variables': vars,
          'variableFiles': varFiles,
          'files': scanCtx.scanParams.files,
          'folders': scanCtx.scanParams.folders
        }
      }
    }
  }

  let tokenResult = await getOrRefreshPcsToken(scanCtx)
  if (tokenResult.failed) {
    return tokenResult
  }

  try {
    const response = await scanCtx.http.postJson(
      scanCtx.pcsBaseUrl + '/iac/v2/scans/' + initResult.scanId,
      triggerRequest,
      {
        'x-redlock-auth': tokenResult.result,
        'content-type': JSON_API_CONTENT_TYPE,
        'accept': JSON_API_CONTENT_TYPE
      }
    );
    if (typeof response.result !== 'undefined' && response.result != null
      && typeof response.result.errors !== 'undefined' && response.result.errors != null) {
      return {
        result: null,
        failed: true,
        errors: response.result.errors.map(function (e) {
          return {
            status: e.status,
            message: e.detail
          }
        })
      }
    }

    return {
      result: initResult,
      failed: false,
      errors: null
    }
  } catch (error) {
    core.error('error : ' + JSON.stringify(error, null, 2));
    if (typeof error.result === 'undefined' || error.result == null
      || typeof error.result.errors === 'undefined' || error.result.errors == null) {
      let message = error.name
      if (typeof error.statusCode !== 'undefined' && error.statusCode != null) {
        message = message + ' : ' + error.statusCode;
      }
      return {
        result: null,
        failed: true,
        errors: [{
          status: 'Internal Error',
          message: message
        }]
      }
    }
    const responseBody = error.result
    let errors = []
    if (responseBody.errors) {
      errors = responseBody.errors.map(function (e) {
        return {
          status: e.status,
          message: e.detail
        }
      })
    } else {
      errors = [{
        status: 'Internal Error',
        message: error.error
      }]
    }
    return {
      result: null,
      failed: true,
      errors: errors
    }
  }
}

async function awaitScanCompletion(scanCtx, scanId) {
  let statusResult = null
  let maxWaitTime = scanCtx.startTime.getTime() + (20 * 60 * 1000)
  while (true) {
    if (maxWaitTime <= (new Date().getTime() + 3000)) {
      statusResult = {
        result: null,
        failed: true,
        errors: [{
          status: 'Time Out',
          message: 'Scan took longer than 20 minutes. Please check status on Prism Cloud for ScanID: ' + scanId
        }]
      }
      break
    }
    if (statusResult != null && statusResult.failed) {
      return statusResult
    }
    // wait for timeout
    await new Promise(resolve => setTimeout(resolve, 2000))

    let tokenResult = await getOrRefreshPcsToken(scanCtx)
    if (tokenResult.failed) {
      return tokenResult
    }

    core.info('Fetching status...')
    try {
      const response = await scanCtx.http.getJson(
        scanCtx.pcsBaseUrl + '/iac/v2/scans/' + scanId + '/status',
        {
          'x-redlock-auth': tokenResult.result,
          'accept': JSON_API_CONTENT_TYPE
        }
      );
      if (typeof response.result !== 'undefined' && response.result != null
        && typeof response.result.errors !== 'undefined' && response.result.errors != null) {
        statusResult = {
          result: null,
          failed: true,
          errors: response.result.errors.map(function (e) {
            return {
              status: e.status,
              message: e.detail
            }
          })
        }
        break
      } else if (response.result.data.attributes.status != 'processing') {
        statusResult = {
          result: {
            scanId: response.result.data.id,
            scanStatus: response.result.data.attributes.status
          },
          failed: false,
          errors: null
        }
        break
      }
    } catch (error) {
      core.error('error : ' + JSON.stringify(error, null, 2));
      if (typeof error.result === 'undefined' || error.result == null
        || typeof error.result.errors === 'undefined' || error.result.errors == null) {
        let message = error.name
        if (typeof error.statusCode !== 'undefined' && error.statusCode != null) {
          message = message + ' : ' + error.statusCode;
        }
        return {
          result: null,
          failed: true,
          errors: [{
            status: 'Internal Error',
            message: message
          }]
        }
      }
      const responseBody = error.result
      let errors = []
      if (responseBody.errors) {
        errors = responseBody.errors.map(function (e) {
          return {
            status: e.status,
            message: e.detail
          }
        })
      } else {
        errors = [{
          status: 'Internal Error',
          message: error.error
        }]
      }
      statusResult = {
        result: null,
        failed: true,
        errors: errors
      }
      break
    }
  }
  return statusResult
}

async function getResult(scanCtx, scanId) {
  let tokenResult = await getOrRefreshPcsToken(scanCtx)
  if (tokenResult.failed) {
    return tokenResult
  }

  try {
    const response = await scanCtx.http.getJson(
      scanCtx.pcsBaseUrl + '/iac/v2/scans/' + scanId + '/results',
      {
        'x-redlock-auth': tokenResult.result,
        'accept': JSON_API_CONTENT_TYPE
      }
    );
    if (typeof response.result !== 'undefined' && response.result != null
      && typeof response.result.errors !== 'undefined' && response.result.errors != null) {
      return {
        result: null,
        failed: true,
        errors: response.result.errors.map(function (e) {
          return {
            status: e.status,
            message: e.detail
          }
        })
      }
    }

    return {
      result: response.result,
      failed: false,
      errors: null
    }
  } catch (error) {
    core.error('error : ' + JSON.stringify(error, null, 2));
    if (typeof error.result === 'undefined' || error.result == null
      || typeof error.result.errors === 'undefined' || error.result.errors == null) {
      let message = error.name
      if (typeof error.statusCode !== 'undefined' && error.statusCode != null) {
        message = message + ' : ' + error.statusCode;
      }
      return {
        result: null,
        failed: true,
        errors: [{
          status: 'Internal Error',
          message: message
        }]
      }
    }
    const responseBody = error.result
    let errors = []
    if (responseBody.errors) {
      errors = responseBody.errors.map(function (e) {
        return {
          status: e.status,
          message: e.detail
        }
      })
    } else {
      errors = [{
        status: 'Internal Error',
        message: error.error
      }]
    }
    return {
      result: null,
      failed: true,
      errors: errors
    }
  }
}

async function getSarifResult(scanCtx, scanId) {
  let tokenResult = await getOrRefreshPcsToken(scanCtx)
  if (tokenResult.failed) {
    return tokenResult
  }

  try {
    const response = await scanCtx.http.getJson(
      scanCtx.pcsBaseUrl + '/iac/v2/scans/' + scanId + '/results/sarif',
      {
        'x-redlock-auth': tokenResult.result,
        'accept': 'application/json'
      }
    );
    if (typeof response.result !== 'undefined' && response.result != null
      && typeof response.result.errors !== 'undefined' && response.result.errors != null) {
      return {
        result: null,
        failed: true,
        errors: response.result.errors.map(function (e) {
          return {
            status: e.status,
            message: e.detail
          }
        })
      }
    }

    return {
      result: response.result,
      failed: false,
      errors: null
    }
  } catch (error) {
    core.error('error : ' + JSON.stringify(error, null, 2));
    if (typeof error.result === 'undefined' || error.result == null
      || typeof error.result.errors === 'undefined' || error.result.errors == null) {
      let message = error.name
      if (typeof error.statusCode !== 'undefined' && error.statusCode != null) {
        message = message + ' : ' + error.statusCode;
      }
      return {
        result: null,
        failed: true,
        errors: [{
          status: 'Internal Error',
          message: message
        }]
      }
    }
    const responseBody = error.result
    let errors = []
    if (responseBody.errors) {
      errors = responseBody.errors.map(function (e) {
        return {
          status: e.status,
          message: e.detail
        }
      })
    } else {
      errors = [{
        status: 'Internal Error',
        message: error.error
      }]
    }
    return {
      result: null,
      failed: true,
      errors: errors
    }
  }
}

async function createGhIssue(octokit, owner, repo, assignee, is_pr, outcome, totalIssues, bodyMd) {
  let title = 'Prisma Cloud IaC Scan '
  if (outcome == 'failed') {
    title += ' Failed - ' + totalIssues + ' Issues found in scan'
  } else if (outcome == 'error') {
    title += 'Error occurred during scan'
  } else {
    return
  }
  if (is_pr) {
    const issue = github.context.issue
    if (issue != null && typeof issue.number !== 'undefined' && issue.number != null) {
      title += ' for pull request #' + issue.number
      bodyMd = 'Issues for pull request ' + github.context.payload.pull_request.html_url + '\n\n' + bodyMd
    }
  }
  return await octokit.issues.create({
    owner: owner,
    repo: repo,
    assignees: [assignee],
    title: title,
    body: bodyMd
  })
}

async function createPullRequestComment(octokit, owner, repo, bodyMd) {
  return await octokit.issues.createComment({
    owner: owner,
    repo: repo,
    issue_number: github.context.payload.pull_request.number,
    body: bodyMd,
  })
}

async function createPullRequestCheck(octokit, owner, repo, outcome, totalIssues, bodyMd) {
  let title = 'Prisma Cloud IaC Scan '
  let conclusion = ''
  if (outcome == 'passed') {
    title += 'Passed'
    conclusion = 'success'
  } else if (outcome == 'failed') {
    title += 'Failed - ' + totalIssues + ' Issues found in scan'
    conclusion = 'action_required'
  } else if (outcome == 'error') {
    title += 'Error occurred during scan'
    conclusion = 'neutral'
  } else {
    return
  }
  const head_sha = github.context.payload.pull_request.head.sha
  return await octokit.checks.create({
    owner: owner,
    repo: repo,
    name: 'Prisma Cloud IaC Scan Result',
    head_sha: head_sha,
    status: 'completed',
    conclusion: conclusion,
    completed_at: new Date().toISOString(),
    output: {
      title: title,
      summary: bodyMd
    }
  })
}

async function generateOutput(scanCtx, scanStatus, result) {
  const data = result.data
  let issueCount = 0
  let highCount = 0
  let medCount = 0
  let lowCount = 0
  const issues = []
  if (data.length > 0) {
    for (var i = 0; i < data.length; i++) {
      const entry = data[i]
      issues.push({
        severity: capitalizeFirstLetter(entry.attributes.severity),
        title: entry.attributes.name,
        docUrl: entry.attributes.docUrl,
        files: entry.attributes.files
      })
      issueCount++
      if (entry.attributes.severity == 'high') {
        highCount++
      } else if (entry.attributes.severity == 'medium') {
        medCount++
      } else if (entry.attributes.severity == 'low') {
        lowCount++
      }
    }

    issues.sort(function (a, b) {
      let r = 0
      if (typeof a.severity !== 'undefined' && b.severity !== 'undefined') {
        r = SORT_ORDER.indexOf(a.severity) - SORT_ORDER.indexOf(b.severity)
      }
      if (r == 0 && typeof a.files !== 'undefined' && b.files !== 'undefined'
        && typeof a.files.length !== 'undefined' && b.files.length !== 'undefined') {
        r = b.files.length - a.files.length
      }
      if (r == 0 && typeof a.title !== 'undefined' && b.title !== 'undefined') {
        r = ('' + a.title).localeCompare(b.title)
      }
      return r
    });
  }

  const operator = scanCtx.failureCriteria.operator.toUpperCase()

  let issuesSnippetMd = ''
  let issuesSnippetLog = ''
  if (issueCount > 0) {
    let issueSnippetSuffix = ' with Severity High: ' + highCount
      + ', Medium: ' + medCount + ', Low: ' + lowCount
    issuesSnippetMd = 'has found **' + issueCount + ' issues**' + issueSnippetSuffix
    issuesSnippetLog = 'has found ' + issueCount + ' issues' + issueSnippetSuffix
  } else {
    issuesSnippetMd = 'found **no issues**'
    issuesSnippetLog = 'found no issues'
  }
  let resultMd = '### Prisma Cloud IaC Scan - ' + capitalizeFirstLetter(scanStatus)
    + '\n\nPrisma Cloud IaC scan ' + issuesSnippetMd + '\nScan **' + scanStatus.toUpperCase()
    + '** as per the configured failure criteria High: '
    + scanCtx.failureCriteria.high + ', Medium: ' + scanCtx.failureCriteria.medium
    + ', Low:  ' + scanCtx.failureCriteria.low + ', Operator: ' + operator + '\n\n';

  let resultLog = 'Prisma Cloud IaC scan status: ' + capitalizeFirstLetter(scanStatus) + '.';
  if (issueCount > 0) {
    resultLog += ' Scan ' + issuesSnippetLog + '. Scan ' + scanStatus.toUpperCase()
      + ' as per the configured failure criteria High: ' + scanCtx.failureCriteria.high
      + ', Medium: ' + scanCtx.failureCriteria.medium
      + ', Low:  ' + scanCtx.failureCriteria.low
      + ', Operator: ' + operator + '.';
  }

  if (issueCount > 0) {
    const issuesOutputMd = await generateIssues(scanCtx, issues)
    resultMd += issuesOutputMd;
    scanCtx.issuesMd = resultMd;
  }

  let hasErrors = false;
  let errorsMsg = '';
  if (typeof result.meta.errorDetails !== 'undefined' && result.meta.errorDetails != null && result.meta.errorDetails.length > 0) {
    const partialFailures = result.meta.errorDetails.map(function (e) {
      return {
        status: e.status,
        message: e.detail
      }
    })

    errorsMsg = await generateError(scanCtx, partialFailures)
    if (errorsMsg.length > 0) {
      resultMd += '\n\n\n### Errors\n\n' + scanCtx.errorMd
      hasErrors = true;
    }
  }

  const mdPath = scanCtx.resultDir + '/result.md';
  fs.writeFileSync(mdPath, resultMd);
  core.setOutput('iac_scan_result', scanStatus);
  core.setOutput('iac_scan_result_path', scanCtx.resultDir);
  if (issueCount > 0) {
    core.setOutput('iac_scan_result_issues_csv_path', scanCtx.resultDir + '/issues.csv');
  }
  if (hasErrors) {
    core.setOutput('iac_scan_result_errors_csv_path', scanCtx.resultDir + '/errors.csv');
  }
  core.setOutput('iac_scan_result_md_path', mdPath);

  const outcomePassed = scanStatus == 'passed'
  if (!scanCtx.tokenMissing) {
    if (scanCtx.is_pr && scanCtx.createPrCheck) {
      const prCheck = await createPullRequestCheck(scanCtx.octokit, scanCtx.owner, scanCtx.repo, scanStatus, issueCount, resultMd)
      core.info('Created check on pull requect: ' + prCheck.data.html_url)
    }
    if (scanCtx.is_pr && scanCtx.createPrComment) {
      const prComment = await createPullRequestComment(scanCtx.octokit, scanCtx.owner, scanCtx.repo, resultMd)
      core.info('Created comment on pull requect: ' + prComment.data.html_url)
    }
    if (!outcomePassed && scanCtx.createIssue) {
      const issue = await createGhIssue(scanCtx.octokit, scanCtx.owner, scanCtx.repo,
        scanCtx.is_pr ? github.context.actor : scanCtx.owner, scanCtx.is_pr, scanStatus, issueCount, resultMd)
      core.info('Created Issue: ' + issue.data.html_url)
    }
  }

  if (outcomePassed) {
    if (issueCount > 0) {
      core.warning(resultLog);
      if (hasErrors) {
        core.warning(errorsMsg);
      }
      core.warning('Prisma Cloud IaC Scan - Please check result artifact for details.');
    } else {
      core.info(resultLog);
      if (hasErrors) {
        core.warning(errorsMsg);
      }
    }
  } else {
    if (issueCount > 0) {
      core.error(resultLog);
    }
    if (hasErrors) {
      core.error(errorsMsg);
    }
    core.setFailed('Prisma Cloud IaC Scan - Please check result artifact for details.');
  }
  core.setOutput('iac_scan_result_summary', resultLog);
}

async function generateIssues(scanCtx, result) {
  const mdheader = ['Severity', 'Policy Name', 'Files']
  const csvheader = ['Severity', 'Policy Name', 'Files', 'Policy URL']
  let mdtableInput = [mdheader]
  let csvRows = []
  for (let i = 0; i < result.length; i++) {
    let r = result[i]
    let docUrl = ''
    if (typeof r.docUrl !== 'undefined' && r.docUrl != null) {
      docUrl = r.docUrl
    }
    let title = r.title
    if (docUrl != null && docUrl.length > 0) {
      title = '[' + title + ']' + '(' + docUrl + ')'
    }
    mdtableInput.push([r.severity, title, r.files.join("<br />")])
    csvRows.push([r.severity, r.title, r.files.join(','), docUrl])
  }
  const csvWriter = createCsvWriter({
    path: scanCtx.resultDir + '/issues.csv',
    header: csvheader
  });
  await csvWriter.writeRecords(csvRows)
  return mdtable(mdtableInput)
}

async function generateError(scanCtx, errors) {
  if (errors != null && errors.length > 0) {
    const errorStr = 'Prisma Cloud IaC Scan - Scan reported ' + errors.length + ' errors.';
    let header = ['Error Status', 'Error Message'];
    let mdtableInput = [header]
    let csvRows = []
    for (let i = 0; i < errors.length; i++) {
      let e = errors[i]
      let message = e.message
      let messageLines = message.split('\n')
      for (let j = 0; j < messageLines.length; j++) {
        let line = messageLines[j];
        if (line == null) {
          continue;
        }
        line = line.trim();
        if (line.length < 1) {
          continue;
        }
        if (j > 0) {
          mdtableInput.push([' ', line])
        } else {
          mdtableInput.push([e.status, line])
        }
      }
      csvRows.push([e.status, messageLines.join('. ')])
    }
    scanCtx.errorMd = '# Error occured while scanning\n\n' + mdtable(mdtableInput);
    const csvWriter = createCsvWriter({
      path: scanCtx.resultDir + '/errors.csv',
      header: header
    });
    await csvWriter.writeRecords(csvRows)
    return errorStr;
  }
  return '';
}

async function getTags(scanCtx) {
  const newTags = {}
  let configFilePath = scanCtx.checkoutPath + '/.prismaCloud/config.yml';
  let configFileExists = fs.existsSync(configFilePath);
  if (!configFileExists) {
    configFilePath = scanCtx.checkoutPath + '/.prismaCloud/config.yaml';
    configFileExists = fs.existsSync(configFilePath);
  }
  if (configFileExists) {
    try {
      const config = yaml.safeLoad(fs.readFileSync(configFilePath, 'utf8'));
      if (typeof config !== 'undefined' && config != null) {
        scanCtx['configYml'] = config;
        if (typeof config.tags !== 'undefined' && config.tags != null) {
          const configTags = config.tags;
          if (Array.isArray(configTags)) {
            for (let i = 0; i < configTags.length; i++) {
              var keyValue = configTags[i].split(':');
              newTags[keyValue[0].trim()] = keyValue[1].trim();
            }
          } else if (typeof configTags === 'object') {
            for (let tagName in configTags) {
              newTags[tagName] = configTags[tagName];
            }
          }
        }
      }
    } catch (e) {
      core.warning('Prisma Cloud IaC Scan - Failed to read tags from config file: ' + configFilePath + '. Error: ' + (error instanceof Error ? error.toString() : error))
    }
  }
  const tagsString = scanCtx.tags;
  if (typeof tagsString !== 'undefined' && tagsString != null) {
    const tagsParts = tagsString.split(',');
    for (let i = 0; i < tagsParts.length; i++) {
      const keyValue = tagsParts[i].trim();
      if (keyValue.length > 0) {
        const colonIdx = keyValue.indexOf(':');
        if (colonIdx < 0) {
          newTags[keyValue] = '';
        } else if (colonIdx > 0) {
          const key = keyValue.substring(0, colonIdx).trim();
          if (key.length > 0) {
            const value = keyValue.substring(colonIdx + 1, keyValue.length).trim();
            newTags[keyValue] = value;
          }
        }
      }
    }
  }
  return newTags
}

function capitalizeFirstLetter(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}