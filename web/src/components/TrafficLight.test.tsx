import { afterEach, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { TrafficLight } from './TrafficLight';

afterEach(cleanup);

// Each legend dot carries its own class; the theme's .tl-green, .tl-yellow and .tl-red set
// the --tl colour that .tl-dot paints.
it('gives every legend dot its class', () => {
  const totals = { active: 3, decommissioned: 0, classes: { green: 1, yellow: 1, red: 1 }, percent: { green: 34, yellow: 33, red: 33 }, health: {} };
  const { container } = render(<TrafficLight totals={totals} />);
  const dots = [...container.querySelectorAll('.tl-dot')];
  expect(dots.map((d) => [...d.classList].find((c) => c !== 'tl-dot'))).toEqual(['tl-green', 'tl-yellow', 'tl-red']);
});
