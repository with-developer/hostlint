-- What the dashboard shows of a host besides its results: the operating system and the labels of its latest scan.
ALTER TABLE hosts ADD COLUMN os TEXT NOT NULL DEFAULT '';
;;
ALTER TABLE hosts ADD COLUMN labels TEXT NOT NULL DEFAULT '';
