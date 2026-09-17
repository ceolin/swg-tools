;;; ghsa-list.el --- Browse GHSA advisories in Org buffers -*- lexical-binding: t; -*-

;; Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>

;; SPDX-License-Identifier: Apache-2.0

;; Author: Flavio Ceolin <flavio.ceolin@gmail.com>
;; Keywords: tools, comm
;; Package-Requires: ((emacs "27.1") (org "9.3"))

;;; Commentary:

;; Read-only Org views over the `ghsa' command from swg-tools.
;;
;;     M-x ghsa-list            list advisories (optionally per state)
;;     M-x ghsa-show-analysis   show the stored analysis of one advisory
;;
;; `ghsa-list' opens an Org buffer grouping advisories by state; each
;; GHSA id is an Org link to its GitHub advisory page.  In that buffer:
;;
;;     a   show the analysis of the advisory at point
;;     g   refresh
;;     n / p   next / previous advisory
;;     q   bury the buffer
;;
;; `ghsa-show-analysis' opens the analysis of a single advisory (defaults
;; to the one at point in a `ghsa-list' buffer, otherwise prompts).
;;
;; The tool is invoked exactly like `ghsa.el' does it -- via
;; `ghsa-command' inside `ghsa-venv-activate' -- so the same
;; customization applies.  This file requires `ghsa' only for that
;; shared configuration and its command builder; it does not pull in
;; Gnus.

;;; Code:

(require 'ghsa)
(require 'org)
(require 'seq)
(require 'subr-x)

(declare-function json-read-from-string "json")

(defcustom ghsa-repo ""
  "GitHub owner/name repository slug passed to the ghsa tool."
  :type 'string
  :group 'ghsa)

(defcustom ghsa-list-buffer "*ghsa advisories*"
  "Name of the buffer used by `ghsa-list'."
  :type 'string
  :group 'ghsa)

(defcustom ghsa-analysis-buffer "*ghsa analysis*"
  "Name of the buffer used by `ghsa-show-analysis'."
  :type 'string
  :group 'ghsa)

(defconst ghsa--states '("draft" "triage" "published" "closed")
  "Advisory states understood by the ghsa tool, in reporting order.")

(defvar-local ghsa--list-states nil
  "States used to build the current `ghsa-list' buffer, for refreshing.")

;;; Running the tool ----------------------------------------------------------

(defun ghsa--parse-json (string)
  "Parse STRING as JSON into alists (objects) and lists (arrays)."
  (if (fboundp 'json-parse-string)
      (json-parse-string string :object-type 'alist :array-type 'list
                         :null-object nil :false-object nil)
    (require 'json)
    (defvar json-object-type)
    (defvar json-array-type)
    (defvar json-key-type)
    (defvar json-null)
    (defvar json-false)
    (let ((json-object-type 'alist)
          (json-array-type 'list)
          (json-key-type 'symbol)
          (json-null nil)
          (json-false nil))
      (json-read-from-string string))))

(defun ghsa--run-json (args)
  "Run the ghsa tool with ARGS synchronously and return parsed JSON output.
Signal a `user-error' (including captured stderr) on failure."
  (let* ((default-directory (or ghsa-directory default-directory))
         (command (ghsa--command args))
         (stderr-file (make-temp-file "ghsa-stderr"))
         (stdout (generate-new-buffer " *ghsa-stdout*")))
    (unwind-protect
        (let ((status (apply #'call-process (car command) nil
                             (list stdout stderr-file) nil (cdr command))))
          (unless (eq status 0)
            (user-error "ghsa %s failed (%s): %s"
                        (car args) status
                        (string-trim
                         (with-temp-buffer
                           (insert-file-contents stderr-file)
                           (buffer-string)))))
          (with-current-buffer stdout
            (condition-case err
                (ghsa--parse-json (buffer-string))
              (error
               (user-error "Could not parse ghsa JSON: %s"
                           (error-message-string err))))))
      (kill-buffer stdout)
      (delete-file stderr-file))))

;;; Field helpers -------------------------------------------------------------

(defun ghsa--field (advisory key)
  "Return KEY from ADVISORY, or nil when absent."
  (alist-get key advisory))

(defun ghsa--advisory-url (advisory)
  "Return the GitHub URL for ADVISORY, deriving one if the tool omitted it."
  (or (ghsa--field advisory 'html_url)
      (format "https://github.com/%s/security/advisories/%s"
              ghsa-repo (ghsa--field advisory 'ghsa_id))))

;;; ghsa-list -----------------------------------------------------------------

(defun ghsa--read-states ()
  "Read advisory states from the minibuffer.
Empty input selects the tool default (draft + triage)."
  (seq-remove #'string-empty-p
              (completing-read-multiple
               "States (empty = draft,triage): " ghsa--states nil t)))

(defun ghsa--state-rank (state)
  "Return the reporting-order rank of STATE."
  (or (seq-position ghsa--states state #'string=) 99))

(defun ghsa--group-by-state (advisories)
  "Group ADVISORIES into (STATE . ITEMS) cells ordered by `ghsa--states'."
  (let (groups)
    (dolist (advisory advisories)
      (let* ((state (or (ghsa--field advisory 'state) "unknown"))
             (cell (assoc state groups)))
        (if cell
            (setcdr cell (cons advisory (cdr cell)))
          (push (cons state (list advisory)) groups))))
    (dolist (cell groups)
      (setcdr cell (nreverse (cdr cell))))
    (sort groups (lambda (a b)
                   (< (ghsa--state-rank (car a)) (ghsa--state-rank (car b)))))))

(defun ghsa--insert-advisory-entry (advisory)
  "Insert an Org entry for ADVISORY, tagging it with its GHSA id."
  (let ((id (ghsa--field advisory 'ghsa_id))
        (start (point)))
    (insert (format "** [[%s][%s]]  %s\n"
                    (ghsa--advisory-url advisory) id
                    (or (ghsa--field advisory 'summary) "")))
    (insert (format "   - severity: %s | CVE: %s | embargo: %s%s\n"
                    (or (ghsa--field advisory 'severity) "-")
                    (or (ghsa--field advisory 'cve_id) "-")
                    (or (ghsa--field advisory 'embargo) "-")
                    (if (ghsa--field advisory 'analysis) " | analysis: yes" "")))
    ;; Tag the whole entry so `ghsa-show-analysis' can act on point.
    (put-text-property start (point) 'ghsa-id id)))

(defun ghsa--insert-list (advisories states)
  "Render ADVISORIES (filtered by STATES) as Org into the current buffer."
  (insert "#+TITLE: GHSA advisories\n"
          "#+STARTUP: showall\n\n"
          (format "%d advisory(ies) — states: %s.\n\n"
                  (length advisories)
                  (if states (string-join states ", ") "draft, triage")))
  (if (null advisories)
      (insert "No advisories found.\n")
    (dolist (group (ghsa--group-by-state advisories))
      (insert (format "* %s (%d)\n" (car group) (length (cdr group))))
      (mapc #'ghsa--insert-advisory-entry (cdr group)))))

;;;###autoload
(defun ghsa-list (&optional states)
  "List GHSA advisories in an Org buffer, grouped by state.
STATES is a list of state names to filter by; interactively it is
read from the minibuffer (empty selects draft + triage)."
  (interactive (list (ghsa--read-states)))
  (setq states (seq-remove #'string-empty-p (or states '())))
  (let ((advisories
         (ghsa--run-json
          (append (list "list" "--json")
                  (mapcan (lambda (s) (list "--state" s)) states))))
        (buf (get-buffer-create ghsa-list-buffer)))
    (with-current-buffer buf
      (let ((inhibit-read-only t))
        (erase-buffer)
        (ghsa--insert-list advisories states))
      (ghsa-list-mode)
      (setq ghsa--list-states states)
      (goto-char (point-min))
      (set-buffer-modified-p nil))
    (pop-to-buffer buf)))

(defun ghsa-list-refresh ()
  "Re-run `ghsa-list' with the states used to build this buffer."
  (interactive)
  (ghsa-list ghsa--list-states))

;;; ghsa-show-analysis --------------------------------------------------------

(defun ghsa--id-at-point ()
  "Return the GHSA id at point, or nil."
  (or (get-text-property (point) 'ghsa-id)
      (save-excursion
        (beginning-of-line)
        (when (re-search-forward
               "GHSA-[0-9a-z]\\{4\\}-[0-9a-z]\\{4\\}-[0-9a-z]\\{4\\}"
               (line-end-position) t)
          (match-string-no-properties 0)))))

(defun ghsa--insert-analysis (advisory)
  "Render ADVISORY and its stored analysis as Org into the current buffer."
  (let ((id (ghsa--field advisory 'ghsa_id))
        (summary (or (ghsa--field advisory 'summary) ""))
        (updated (ghsa--field advisory 'analysis_updated_at))
        (analysis (ghsa--field advisory 'analysis)))
    (insert (format "#+TITLE: %s\n" id))
    (unless (string-empty-p summary)
      (insert (format "#+SUBTITLE: %s\n" summary)))
    (insert "#+STARTUP: showall\n\n"
            (format "- Advisory: [[%s][%s]]\n" (ghsa--advisory-url advisory) id))
    (dolist (pair '(("CVE" . cve_id) ("Severity" . severity) ("State" . state)))
      (when (ghsa--field advisory (cdr pair))
        (insert (format "- %s: %s\n" (car pair)
                        (ghsa--field advisory (cdr pair))))))
    (insert "\n")
    (if (or (null analysis) (string-empty-p analysis))
        (insert (format "* Analysis\n\nNo analysis stored for %s.\n\n"
                        id)
                (format "Add one with =ghsa update %s --analysis FILE=.\n" id))
      (insert (format "* Analysis%s\n\n"
                      (if updated (format " (updated %s)" updated) ""))
              analysis)
      (unless (string-suffix-p "\n" analysis) (insert "\n")))))

;;;###autoload
(defun ghsa-show-analysis (ghsa-id)
  "Show the stored analysis for GHSA-ID in an Org buffer.
Interactively, default to the advisory at point (in a `ghsa-list'
buffer) and otherwise prompt for the id."
  (interactive
   (let ((default (ghsa--id-at-point)))
     (list (read-string (if default
                            (format "GHSA id (default %s): " default)
                          "GHSA id: ")
                        nil nil default))))
  (setq ghsa-id (string-trim ghsa-id))
  (when (string-empty-p ghsa-id)
    (user-error "No GHSA id given"))
  (let ((advisory (ghsa--run-json (list "show" ghsa-id "--json")))
        (buf (get-buffer-create ghsa-analysis-buffer)))
    (with-current-buffer buf
      (let ((inhibit-read-only t))
        (erase-buffer)
        (ghsa--insert-analysis advisory))
      (ghsa-analysis-mode)
      (goto-char (point-min))
      (set-buffer-modified-p nil))
    (pop-to-buffer buf)))

;;; Major modes ---------------------------------------------------------------

(defvar ghsa-list-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "a") #'ghsa-show-analysis)
    (define-key map (kbd "g") #'ghsa-list-refresh)
    (define-key map (kbd "n") #'org-next-visible-heading)
    (define-key map (kbd "p") #'org-previous-visible-heading)
    (define-key map (kbd "q") #'quit-window)
    map)
  "Keymap for `ghsa-list-mode'.")

(define-derived-mode ghsa-list-mode org-mode "GHSA-List"
  "Major mode for browsing GHSA advisories.
\\{ghsa-list-mode-map}"
  (setq buffer-read-only t))

(defvar ghsa-analysis-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "q") #'quit-window)
    map)
  "Keymap for `ghsa-analysis-mode'.")

(define-derived-mode ghsa-analysis-mode org-mode "GHSA-Analysis"
  "Major mode for viewing a single GHSA advisory analysis.
\\{ghsa-analysis-mode-map}"
  (setq buffer-read-only t))

(provide 'ghsa-list)
;;; ghsa-list.el ends here
