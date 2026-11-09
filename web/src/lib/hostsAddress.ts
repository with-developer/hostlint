// The address of the host list as the user last left it, so the "back to hosts" link of a host page returns to the
// same filtered list as the browser's back button does.
let last = "#/hosts";

export function rememberHostsAddress(address: string): void {
  last = address;
}

export function lastHostsAddress(): string {
  return last;
}
