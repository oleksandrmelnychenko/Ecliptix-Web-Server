-- Script to clear incompatible protocol state after nonce format change
-- Run this against the EcliptixMemberships database

-- Clear all protocol actor persistent state
DELETE FROM EventJournal WHERE PersistenceId LIKE 'connect-%';
DELETE FROM SnapshotStore WHERE PersistenceId LIKE 'connect-%';
DELETE FROM journal_metadata WHERE PersistenceId LIKE 'connect-%';

-- Clear system actor state if needed
DELETE FROM EventJournal WHERE PersistenceId LIKE 'protocol-system-%';
DELETE FROM SnapshotStore WHERE PersistenceId LIKE 'protocol-system-%';
DELETE FROM journal_metadata WHERE PersistenceId LIKE 'protocol-system-%';

-- Verify cleanup
SELECT 'EventJournal' as TableName, COUNT(*) as RemainingRecords 
FROM EventJournal 
WHERE PersistenceId LIKE 'connect-%' OR PersistenceId LIKE 'protocol-system-%'
UNION ALL
SELECT 'SnapshotStore', COUNT(*) 
FROM SnapshotStore 
WHERE PersistenceId LIKE 'connect-%' OR PersistenceId LIKE 'protocol-system-%'
UNION ALL
SELECT 'journal_metadata', COUNT(*) 
FROM journal_metadata 
WHERE PersistenceId LIKE 'connect-%' OR PersistenceId LIKE 'protocol-system-%';

PRINT 'Protocol state cleared. All connections will need to re-establish secure channels.';