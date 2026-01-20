# Intentionally no shebang here - this script should be sourced.

# Provides functions for adding sections to gitlab CI output.
# See <https://docs.gitlab.com/ee/ci/jobs/job_logs.html#custom-collapsible-sections>
#
# Some undocumented behaviors discovered experimentally:
# * Section titles must be unique, but aren't displayed in the rendered UI.
#   Only the section *descriptions* are displayed.
# * Sections can be nested, which explains why the section-end string has to specify
#   the title of the section that they are ending.
# * Likewise, yes, sections without a section-end string don't work properly in
#   the UI.
#
# For ease of use we don't expose the section-nesting functionality in the API
# below.  In return:
# * `section_end` doesn't need to specify which section it's
#    ending.
# * `section_start` automatically ends the current section.
# * We automatically generate section-titles (which aren't displayed).

# Tell shellcheck the expected shell:
# shellcheck shell=bash

# Track the current section
current_section_number=0
current_section_title=""
current_section_description=""
current_section_start_time=""

# starts a section (first ending the current one, if any)
function section_start () {
  local section_description="${1}"

  # If we're already in a section, end it.
  if [ -n "$current_section_title" ]; then
    section_end
  fi

  local now
  now=$(date +%s)

  ((current_section_number+=1))
  current_section_title="section-$current_section_number"
  current_section_description="$section_description"
  current_section_start_time="$now"

  # gitlab magic string to start the section
  echo -e "section_start:$now:${current_section_title}[collapsed=true]\r\e[0K${current_section_description}"
}

# ends the current section.
function section_end () {
  local now
  now=$(date +%s)

  # While gitlab shows the duration of collapsed sections,
  # it doesn't properly collapse sections whose start has "scrolled off".
  # So show the duration here too, with a nice grep'able prefix.
  echo "SECTION-END: '$current_section_description' finished in $((now-current_section_start_time)) seconds"

  # gitlab magic string to end the section
  echo -e "section_end:$now:${current_section_title}\r\e[0K"

  # clear section vars
  current_section_title=""
  current_section_description=""
  current_section_start_time=""
}
