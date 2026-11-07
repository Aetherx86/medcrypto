// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Consent state, and nothing else. Patients and studies appear only as hashes, so no health information
/// goes on chain. Hospital daemons read this with eth_call, and never need to send a transaction.
contract ConsentRegistry {
    address public owner;

    /// Who may grant and revoke for a patient: the patient's own wallet, or a hospital's consent desk.
    mapping(bytes32 => address) public controllerOf;
    /// The time at which consent ends, by patient and scope. Zero means no consent.
    mapping(bytes32 => mapping(bytes32 => uint64)) public consentUntil;
    /// The study's approved epoch. Studies start as not approved.
    mapping(bytes32 => mapping(uint64 => bool)) public studyActive;

    event ControllerSet(bytes32 indexed patient, address controller);
    event ConsentChanged(bytes32 indexed patient, bytes32 indexed scope, uint64 validUntil);
    event StudyChanged(bytes32 indexed study, uint64 epoch, bool active);

    error NotOwner();
    error NotController();

    constructor() {
        owner = msg.sender;
    }

    function setController(bytes32 patient, address controller) external {
        // The owner assigns a controller once. After that, only the controller can hand it on.
        address current = controllerOf[patient];
        if (current == address(0) ? msg.sender != owner : msg.sender != current) {
            revert NotController();
        }
        controllerOf[patient] = controller;
        emit ControllerSet(patient, controller);
    }

    function grantConsent(bytes32 patient, bytes32 scope, uint64 validUntil) external {
        if (msg.sender != controllerOf[patient]) revert NotController();
        consentUntil[patient][scope] = validUntil;
        emit ConsentChanged(patient, scope, validUntil);
    }

    function revokeConsent(bytes32 patient, bytes32 scope) external {
        if (msg.sender != controllerOf[patient]) revert NotController();
        consentUntil[patient][scope] = 0;
        emit ConsentChanged(patient, scope, 0);
    }

    function setStudy(bytes32 study, uint64 epoch, bool active) external {
        if (msg.sender != owner) revert NotOwner();
        studyActive[study][epoch] = active;
        emit StudyChanged(study, epoch, active);
    }

    function isAuthorized(bytes32 patient, bytes32 scope) external view returns (bool) {
        return consentUntil[patient][scope] > block.timestamp;
    }

    function isStudyActive(bytes32 study, uint64 epoch) external view returns (bool) {
        return studyActive[study][epoch];
    }
}
