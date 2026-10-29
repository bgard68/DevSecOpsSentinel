/**
 * Structural rules for the import graph, enforced in CI the same way the
 * layering tests pin the .NET assemblies: the type checker proves each import
 * individually sound, but says nothing about the shape they add up to.
 *
 * Every rule is an error on purpose. A warning in CI output that fails nothing
 * is read once, scrolled past forever.
 *
 * @type {import('dependency-cruiser').IConfiguration}
 */
module.exports = {
  forbidden: [
    {
      name: 'no-circular',
      severity: 'error',
      comment:
        'A cycle has no first module, so there is no order in which its parts ' +
        'can be understood, tested, or torn apart. Break it with an interface ' +
        'or by moving the shared piece to its own module.',
      from: {},
      to: { circular: true },
    },
    {
      name: 'not-to-test',
      severity: 'error',
      comment:
        'Production code importing a test file or the test setup drags the ' +
        'test toolchain into the shipped bundle, and couples runtime behaviour ' +
        'to code that is free to change whenever a test needs it to.',
      from: { pathNot: ['\\.test\\.(ts|tsx)$', '^src/test/'] },
      to: { path: ['\\.test\\.(ts|tsx)$', '^src/test/'] },
    },
    {
      name: 'not-to-unresolvable',
      severity: 'error',
      comment:
        'An import that does not resolve only fails at build or run time, ' +
        'which is later than a pull request check needs to hear about it.',
      from: {},
      to: { couldNotResolve: true },
    },
  ],
  options: {
    // Resolve through node_modules so a missing package is distinguishable
    // from a typo, but do not analyse what lies inside them.
    doNotFollow: { path: 'node_modules' },

    // The app tsconfig, not the solution-style root one: it is the only one
    // whose include covers src/, and Bundler resolution lives there.
    tsConfig: { fileName: 'tsconfig.app.json' },

    // Count type-only imports as dependencies. models.ts is mostly types; a
    // cycle through it is still a cycle someone has to reason about.
    tsPreCompilationDeps: true,

    enhancedResolveOptions: {
      exportsFields: ['exports'],
      conditionNames: ['import', 'require', 'node', 'default', 'types'],
      mainFields: ['module', 'main', 'types', 'typings'],
    },
  },
};
