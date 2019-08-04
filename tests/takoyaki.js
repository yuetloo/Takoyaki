'use strict';

const ethers = require('ethers');
const Takoyaki = require('../lib');

const getEvent = (contract, receipt, eventName) =>
  receipt.logs
    .map(log => contract.interface.parseLog(log))
    .filter(Boolean)
    .find(({ name }) => name === eventName);

const register = async (provider, signer, label) => {
  const takoyaki = Takoyaki.connect(signer);
  const salt = ethers.utils.keccak256(ethers.utils.randomBytes(32));

  let tx = await takoyaki.commit(
    label,
    signer.address,
    salt,
    ethers.constants.AddressZero,
    0
  );
  let receipt = await tx.wait();

  await provider.mineBlocks(5);

  tx = await takoyaki.reveal(label, signer.address, salt);
  receipt = await tx.wait();
  return receipt;
};

const getTokenId = (contract, receipt) => {
  const transferEvent = getEvent(contract, receipt, 'Transfer');

  if (!transferEvent) {
    throw new Error('Missing transfer event');
  }

  if (transferEvent.values.length !== 3) {
    throw new Error(
      `Expect 3 parameters for the transfer event, but got ${
        transferEvent.values.length
      }`
    );
  }

  const tokenId = transferEvent.values[2];
  return tokenId;
};

const safeTransfer = async (owner, newOwner, tokenId, data) => {
  const takoyaki = Takoyaki.connect(owner);

  const command = data
    ? 'safeTransferFrom(address,address,uint256,bytes)'
    : 'safeTransferFrom(address,address,uint256)';

  const tx = data
    ? await takoyaki[command](owner.address, newOwner.address, tokenId, data)
    : await takoyaki[command](owner.address, newOwner.address, tokenId);

  const receipt = await tx.wait();
  return receipt;
};

const submitBlindedCommit = async (provider, signer, label) => {
  const salt = ethers.utils.keccak256(ethers.utils.randomBytes(32));

  const takoyaki = Takoyaki.connect(signer);
  let tx = await takoyaki.commit(
    label,
    signer.address,
    salt,
    ethers.constants.AddressZero,
    0
  );

  const receipt = await tx.wait();
  await provider.mineBlocks(5);

  const commitEvent = getEvent(takoyaki, receipt, 'Committed');
  if (!commitEvent) {
    throw new Error('missing commit event');
  }

  if (commitEvent.values.length !== 2) {
    throw new Error(
      `Expect 2 parameters for the commit event, but got ${
        commitEvent.values.length
      }`
    );
  }

  const blindedCommit = commitEvent.values[1];
  return blindedCommit;
};

module.exports = {
  connect: Takoyaki.connect,
  getEvent,
  getTokenId,
  register,
  safeTransfer,
  submitBlindedCommit
};
