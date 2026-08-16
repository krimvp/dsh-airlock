/**
 * The label lattice.
 *
 * Two independent axes. Trust answers "could an attacker have written this".
 * Sensitivity answers "what happens if this escapes". A join takes the upper
 * bound on both axes, so combining content never lowers a label.
 *
 *   trust:        user   < workspace    < untrusted
 *   sensitivity:  public < confidential < secret
 */

/** Who could have authored the content. */
export type Trust = 'user' | 'workspace' | 'untrusted'

/** What the content costs if it escapes. */
export type Sensitivity = 'public' | 'confidential' | 'secret'

const TRUST_ORDER: readonly Trust[] = ['user', 'workspace', 'untrusted']
const SENSITIVITY_ORDER: readonly Sensitivity[] = ['public', 'confidential', 'secret']

/** One point in the lattice. */
export interface Label {
  readonly trust: Trust
  readonly sensitivity: Sensitivity
}

/** The lattice bottom: content the user typed, carrying nothing sensitive. */
export const BOTTOM: Label = Object.freeze({ trust: 'user', sensitivity: 'public' })

/**
 * Rank a trust value.
 * @param trust - the value to rank.
 * @returns its index in the ordering; `0` for an unknown value.
 */
export function trustRank(trust: Trust): number {
  const rank = TRUST_ORDER.indexOf(trust)
  return rank < 0 ? 0 : rank
}

/**
 * Rank a sensitivity value.
 * @param sensitivity - the value to rank.
 * @returns its index in the ordering; `0` for an unknown value.
 */
export function sensitivityRank(sensitivity: Sensitivity): number {
  const rank = SENSITIVITY_ORDER.indexOf(sensitivity)
  return rank < 0 ? 0 : rank
}

/**
 * Join two labels.
 * @param a - the first label.
 * @param b - the second label.
 * @returns the least upper bound on both axes.
 */
export function join(a: Label, b: Label): Label {
  return {
    trust: trustRank(b.trust) > trustRank(a.trust) ? b.trust : a.trust,
    sensitivity: sensitivityRank(b.sensitivity) > sensitivityRank(a.sensitivity)
      ? b.sensitivity
      : a.sensitivity,
  }
}

/**
 * Join a sequence of labels.
 * @param labels - the labels to combine.
 * @returns the least upper bound of every label, or {@link BOTTOM} when empty.
 */
export function joinAll(labels: Iterable<Label>): Label {
  let result = BOTTOM
  for (const label of labels) result = join(result, label)
  return result
}

/**
 * Test whether a label reaches a trust level.
 * @param label - the label to test.
 * @param trust - the level to reach.
 * @returns `true` when the label's trust is at or above `trust`.
 */
export function trustAtLeast(label: Label, trust: Trust): boolean {
  return trustRank(label.trust) >= trustRank(trust)
}

/**
 * Test whether a label reaches a sensitivity level.
 * @param label - the label to test.
 * @param sensitivity - the level to reach.
 * @returns `true` when the label's sensitivity is at or above `sensitivity`.
 */
export function sensitivityAtLeast(label: Label, sensitivity: Sensitivity): boolean {
  return sensitivityRank(label.sensitivity) >= sensitivityRank(sensitivity)
}

/**
 * Render a label for a log line or a denial message.
 * @param label - the label to render.
 * @returns the two axes in `trust=… sensitivity=…` form.
 */
export function formatLabel(label: Label): string {
  return `trust=${label.trust} sensitivity=${label.sensitivity}`
}
