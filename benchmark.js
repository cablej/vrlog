var axios = require("axios");
var exec = require("child_process").exec;

const host = "http://localhost:8084/";

function printTimes(start, upTo, batchSize, times, type) {
  if (times.length > 0) {
    console.log(
      type +
        ", " +
        start +
        ", " +
        upTo +
        ", " +
        times.reduce((a, b) => a + b) / times.length +
        ", " +
        times.reduce((a, b) => a + b)
    );
  }
}

async function testAddVoter(start, upTo, batchSize) {
  console.error("Adding voter " + String(start));
  times = {
    addVoter: [],
    getVoter: [],
    membershipProof: [],
    verifyMembership: []
  };
  while (start < upTo) {
    newVersion = start + batchSize;
    if (newVersion > upTo) newVersion = upTo;
    body = {
      start_id: start,
      end_id: newVersion,
      voter: {
        firstName: "Test",
        lastName: "Test",
        ssn: "1234",
        status: "active"
      }
    };
    start = newVersion;
    resp = await axios.post(host + "batchVoter", body);
    times["addVoter"].push(parseInt(resp.headers["response-time"]));

    id = resp.data.id;
    resp = await axios.get(host + "voter?id=" + id);
    times["getVoter"].push(parseInt(resp.headers["response-time"]));

    resp = await axios.get(host + "voter/prove?id=" + id);
    times["membershipProof"].push(parseInt(resp.headers["response-time"]));

    resp = await axios.get(host + "voter/prove?id=" + id);
    times["membershipProof"].push(parseInt(resp.headers["response-time"]));

    resp = await axios.post(host + "voter/verify", resp.data);
    times["verifyMembership"].push(parseInt(resp.headers["response-time"]));
  }
  for (var type in times) {
    printTimes(start, upTo, batchSize, times[type], type);
  }
}

async function testVerifyAppendOnly(start, upTo, count) {
  console.error("Verifying append only " + String(start));
  resp = await axios.get(host + "version");
  version = parseInt(resp.data.version);
  times = {
    proveAppendOnly: [],
    verifyAppendOnly: []
  };

  resp = await axios.get(
    host + "proveAppendOnly?first_tree_size=" + String(version - 1)
  );
  times["proveAppendOnly"].push(parseInt(resp.headers["response-time"]));

  resp = await axios.post(host + "verifyAppendOnly", resp.data);
  times["verifyAppendOnly"].push(parseInt(resp.headers["response-time"]));

  for (var type in times) {
    printTimes(start, upTo, count, times[type], type);
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function testSuite() {
  start = 0;
  max = start + 100000;
  count = 2500;
  while (true) {
    console.error("Starting " + String(start));
    await testAddVoter(start, max, count);
    await sleep(60 * 1000);
    await testVerifyAppendOnly(start, max, count);
    start = max;
    max += 100000;
  }
}

testSuite();
