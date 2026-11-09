// The address of a list (hosts, controls) as the user last left it, so the "back" link of a detail page returns to the
// same filtered list as the browser's back button does.
export type ListName = "hosts" | "controls";

const last: Record<ListName, string> = { hosts: "#/hosts", controls: "#/controls" };

export function rememberListAddress(list: ListName, address: string): void {
  last[list] = address;
}

export function lastListAddress(list: ListName): string {
  return last[list];
}
