MODIFIED: DirProvider now has download_task_handle().
          There's a default implementation, so this isn't a breaking change.
MODIFIED: DirBootstrapStatus now has a blockage() method.
BREAKING: DirStatus is no longer a public type. 
          (Nothing would actually give you one.)
