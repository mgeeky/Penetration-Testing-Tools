function Find-CLSIDForProgID($ProgId) {
    Get-ChildItem REGISTRY::HKEY_CLASSES_ROOT\CLSID -Include PROGID -Recurse | where {$_.GetValue("") -match $ProgId }
}