;;; ghsa.el --- Draft GHSA advisories from Gnus articles -*- lexical-binding: t; -*-

;; Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>

;; SPDX-License-Identifier: Apache-2.0

;; Author: Flavio Ceolin <flavio.ceolin@gmail.com>
;; Keywords: mail, comm, tools
;; Package-Requires: ((emacs "27.1"))

;;; Commentary:

;; Send the Gnus article you are reading -- a vulnerability report email
;; -- to the `ghsa generate' command from swg-tools, which drafts a
;; GitHub Security Advisory from it.
;;
;; With a Gnus article selected (in the summary or article buffer):
;;
;;     M-x ghsa-generate-from-article
;;
;; The raw article is piped to the tool on standard input and the run is
;; asynchronous, so Emacs stays responsive while the model call happens.
;; Output (progress on stderr, results on stdout) appears in the
;; `ghsa-output-buffer'.  By default the tool writes the advisory and the
;; GitHub JSON payload under advisories/ in `ghsa-directory'; with a
;; prefix argument the advisory is previewed in the buffer instead
;; (passes --stdout).
;;
;; Suggested binding:
;;
;;     (with-eval-after-load 'gnus-sum
;;       (define-key gnus-summary-mode-map (kbd "v g")
;;                   #'ghsa-generate-from-article))
;;
;; The tool is run inside a Python virtualenv: `ghsa-venv-activate' is
;; sourced in a shell before `ghsa-command' is exec'd.  Point that at a
;; virtualenv whose Python has the swg-tools dependencies installed, or
;; set it to nil to run `ghsa-command' directly (e.g. via `uv').

;;; Code:

(require 'gnus)
(require 'gnus-sum)
(require 'gnus-art)

(defgroup ghsa nil
  "Draft GHSA advisories from Gnus articles."
  :group 'gnus
  :prefix "ghsa-")

(defcustom ghsa-directory
  (when load-file-name
    (file-name-as-directory
     (expand-file-name ".." (file-name-directory load-file-name))))
  "Directory the ghsa tool is run from (the swg-tools checkout).
Defaults to the parent of the directory this file was loaded from."
  :type '(choice (const :tag "Emacs default directory" nil) directory))

(defcustom ghsa-command '("python" "scripts/ghsa")
  "Command used to invoke the ghsa tool.
A list of strings: the program followed by any leading arguments,
resolved relative to `ghsa-directory'.  When `ghsa-venv-activate'
is set the program is resolved from the activated virtualenv."
  :type '(repeat string))

(defcustom ghsa-venv-activate
  (expand-file-name "~/p/zephyrproject/.venv/bin/activate")
  "Path to a Python virtualenv activate script to source before running.
It is sourced in `ghsa-shell' and then `ghsa-command' is exec'd,
so the tool runs inside that virtualenv.  Set to nil to run
`ghsa-command' directly without activating a virtualenv."
  :type '(choice (const :tag "No virtualenv" nil) file))

(defcustom ghsa-shell "zsh"
  "Shell used to source `ghsa-venv-activate' and launch the command."
  :type 'string)

(defcustom ghsa-output-buffer "*ghsa generate*"
  "Name of the buffer that receives ghsa output."
  :type 'string)

(defun ghsa--article-text ()
  "Return the raw text of the currently selected Gnus article.
Signals a `user-error' when Gnus is not running or no article is
selected."
  (unless (gnus-alive-p)
    (user-error "Gnus is not running"))
  (cond
   ((derived-mode-p 'gnus-summary-mode)
    ;; Make sure the article under point is the selected one.
    (gnus-summary-select-article))
   ((derived-mode-p 'gnus-article-mode)
    ;; The original-article buffer already holds this article.
    nil)
   (t
    (user-error "Not in a Gnus summary or article buffer")))
  (let ((buf (get-buffer gnus-original-article-buffer)))
    (unless (buffer-live-p buf)
      (user-error "No Gnus article is selected"))
    (with-current-buffer buf
      (buffer-substring-no-properties (point-min) (point-max)))))

(defun ghsa--sentinel (proc event)
  "Report completion of ghsa PROC in the minibuffer given EVENT."
  (when (memq (process-status proc) '(exit signal))
    (let ((buf (process-buffer proc)))
      (when (buffer-live-p buf)
        (with-current-buffer buf
          (goto-char (point-max))
          (insert (format "\n--- ghsa %s" (string-trim event)))))
      (if (and (eq (process-status proc) 'exit)
               (zerop (process-exit-status proc)))
          (message "ghsa generate finished (see %s)" (buffer-name buf))
        (message "ghsa generate failed (see %s)" (buffer-name buf))))))

;;;###autoload
(defun ghsa-generate-from-article (&optional preview)
  "Run `ghsa generate' on the current Gnus article.

The raw article is fed to the tool on standard input.  With a
prefix argument PREVIEW, pass --stdout so the advisory is printed
to the output buffer instead of written to files."
  (interactive "P")
  (let* ((email (ghsa--article-text))
         (default-directory (or ghsa-directory default-directory))
         (ghsa-args (append ghsa-command
                            (list "generate" "--email" "-")
                            (when preview '("--stdout"))))
         (activate (and ghsa-venv-activate
                        (expand-file-name ghsa-venv-activate)))
         (command
          (if activate
              ;; Source the virtualenv, then hand the process over to the
              ;; tool so stdin/EOF and the exit status pass straight through.
              (list ghsa-shell "-c"
                    (format "source %s && exec %s"
                            (shell-quote-argument activate)
                            (mapconcat #'shell-quote-argument ghsa-args " ")))
            ghsa-args))
         (buf (get-buffer-create ghsa-output-buffer)))
    (when (and activate (not (file-exists-p activate)))
      (user-error "Virtualenv activate script not found: %s" activate))
    (unless (executable-find (car command))
      (user-error "Cannot find launcher %S on PATH" (car command)))
    (with-current-buffer buf
      (setq buffer-read-only nil)
      (erase-buffer)
      (insert (format "$ %s\n(cwd: %s)\n\n"
                      (if activate
                          (nth 2 command)
                        (mapconcat #'identity ghsa-args " "))
                      default-directory)))
    (display-buffer buf)
    (let ((proc (make-process
                 :name "ghsa-generate"
                 :buffer buf
                 :command command
                 :connection-type 'pipe
                 :noquery t
                 :sentinel #'ghsa--sentinel)))
      (process-send-string proc email)
      (process-send-eof proc)
      (message "ghsa generate running…")
      proc)))

(provide 'ghsa)
;;; ghsa.el ends here
