CREATE TABLE storage_usage (bytes INTEGER NOT NULL CHECK (bytes >= 0)) STRICT;
INSERT INTO storage_usage VALUES (
    (SELECT COALESCE(SUM(length(manifest)), 0) FROM shares) +
    (SELECT COALESCE(SUM(size), 0) FROM files) +
    (SELECT COALESCE(SUM(size), 0) FROM blob_garbage)
);

CREATE TRIGGER account_manifest AFTER UPDATE OF manifest ON shares BEGIN
    UPDATE storage_usage SET bytes = bytes - COALESCE(length(OLD.manifest), 0)
                                          + COALESCE(length(NEW.manifest), 0);
END;

CREATE TRIGGER account_file AFTER INSERT ON files BEGIN
    UPDATE storage_usage SET bytes = bytes + NEW.size;
END;

CREATE TRIGGER account_replacement AFTER UPDATE OF blob_key ON files BEGIN
    INSERT INTO blob_garbage VALUES (OLD.blob_key, OLD.size);
    UPDATE storage_usage SET bytes = bytes + NEW.size;
END;

CREATE TRIGGER queue_removed_file AFTER DELETE ON files BEGIN
    INSERT INTO blob_garbage VALUES (OLD.blob_key, OLD.size);
END;

CREATE TRIGGER account_unlink AFTER DELETE ON blob_garbage BEGIN
    UPDATE storage_usage SET bytes = bytes - OLD.size;
END;
