/**
 * [SECURITY FIX — Vulnerability 7: Broken access control (IDOR on cases)] FIXED
 *
 * Centralizes who may view vs modify a case: admins always; view also for assigned officer
 * and assigned team members; modify/resolve only for assigned officer or admin.
 * Used by routes/caseRoutes.js so users cannot read or edit cases by guessing case IDs alone.
 */
const Team = require('../models/Team');

const userIdString = (user) => (user?.id ?? user?._id)?.toString();

const isAdmin = (user) => user?.role === 'ADMIN';

const isAssignedOfficer = (user, caseDoc) => {
    if (!caseDoc?.assignedOfficer) {
        return false;
    }
    const officerId = caseDoc.assignedOfficer._id ?? caseDoc.assignedOfficer;
    return officerId.toString() === userIdString(user);
};

async function isAssignedTeamMember(user, caseDoc) {
    if (!caseDoc?.assignedTeam) {
        return false;
    }

    const teamRef = caseDoc.assignedTeam;
    let members = teamRef.members;

    if (!members) {
        const teamId = teamRef._id ?? teamRef;
        const team = await Team.findById(teamId).select('members').lean();
        members = team?.members;
    }

    if (!members?.length) {
        return false;
    }

    const uid = userIdString(user);
    return members.some((member) => member.officer?.toString() === uid);
}

async function canViewCase(user, caseDoc) {
    if (isAdmin(user)) {
        return true;
    }
    if (isAssignedOfficer(user, caseDoc)) {
        return true;
    }
    return isAssignedTeamMember(user, caseDoc);
}

async function canModifyCase(user, caseDoc) {
    if (isAdmin(user)) {
        return true;
    }
    return isAssignedOfficer(user, caseDoc);
}

function denyCaseAccess(res) {
    return res.status(403).json({
        message: 'Access denied: you do not have permission for this case'
    });
}

module.exports = {
    canViewCase,
    canModifyCase,
    denyCaseAccess,
    isAdmin,
    userIdString
};
