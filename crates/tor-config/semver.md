ADDED: CfgPathError::VariableInterpolationNotSupported
ADDED: CfgPathError::HomeDirInterpolationNotSupported
FIXED: Build with `expand-paths` disabled fixed
BREAKING: Without `expand-paths`, de-duplicate `$` and reject variable and homedir interpolation
