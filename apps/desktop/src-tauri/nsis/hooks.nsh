; MaxQ NSIS Lifecycle Hooks (Tauri v2 `bundle.windows.nsis.installerHooks`)
; - NSIS_HOOK_POSTINSTALL: automatically refreshes an already-installed MaxQTunService
;   so overwrite upgrades never leave stale `maxq-service.exe` / `sing-box.exe` binaries
;   or outdated GUI hashes in `%ProgramData%\MaxQ\service-bin`.
; - NSIS_HOOK_PREUNINSTALL: gracefully closes any running MaxQ instance, clears any
;   stranded loopback Windows system proxy settings across HKCU + HKU, and stops/uninstalls
;   MaxQTunService plus `%ProgramData%\MaxQ`.

!macro NSIS_HOOK_POSTINSTALL
  ; Only upgrade MaxQTunService if the user had previously installed it (exit code 0).
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query MaxQTunService'
  Pop $0
  Pop $1
  ${If} $0 == 0
    ${If} ${FileExists} "$INSTDIR\resources\maxq-service.exe"
      nsExec::ExecToLog '"$INSTDIR\resources\maxq-service.exe" install'
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; 1. Politely ask any running MaxQ window to close so it cleans up its own session proxy.
  FindWindow $0 "" "MaxQ — Powered by JaxCore sing-box"
  ${If} $0 != 0
    SendMessage $0 0x0010 0 0 /TIMEOUT=2000
    Sleep 1200
  ${EndIf}

  ; 2. Fallback loopback system-proxy recovery (covers HKCU + loaded HKU hives).
  ${If} ${FileExists} "$INSTDIR\maxq-desktop.exe"
    nsExec::ExecToLog '"$INSTDIR\maxq-desktop.exe" --cleanup-sysproxy'
  ${ElseIf} ${FileExists} "$INSTDIR\MaxQ.exe"
    nsExec::ExecToLog '"$INSTDIR\MaxQ.exe" --cleanup-sysproxy'
  ${EndIf}

  ; 3. Stop, unregister, and remove MaxQTunService + %ProgramData%\MaxQ.
  ${If} ${FileExists} "$INSTDIR\resources\maxq-service.exe"
    nsExec::ExecToLog '"$INSTDIR\resources\maxq-service.exe" uninstall'
  ${EndIf}
!macroend
