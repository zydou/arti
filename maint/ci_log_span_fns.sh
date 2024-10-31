# Intentionally no shebang here - this script should be sourced.

# Provides functions for adding sections to gitlab CI output.
# See https://docs.gitlab.com/ee/ci/jobs/job_logs.html#custom-collapsible-sections

# Tell shellcheck the expected shell:
# shellcheck shell=bash

# function for starting the section
function section_start () {
  local section_title="${1}"
  local section_description="${2:-$section_title}"

  echo -e "section_start:$(date +%s):${section_title}[collapsed=true]\r\e[0K${section_description}"
}

# Function for ending the section
function section_end () {
  local section_title="${1}"

  echo -e "section_end:$(date +%s):${section_title}\r\e[0K"
}
