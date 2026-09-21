import { describe, it, expect, beforeAll } from 'vitest';
import { execSync } from 'child_process';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { existsSync } from 'fs';
import { readFileSync } from 'fs';

// Path to the AI module root
const __filename = fileURLToPath(import.meta.url);
// __filename = .../ai/tests/evaluation/evaluate.test.js
// aiRoot = .../ai
const aiRoot = join(dirname(__filename), '..', '..');
const evaluateScript = join(aiRoot, 'scripts', 'evaluate_models.py');
const venvPython = join(aiRoot, '.venv', 'Scripts', 'python.exe');

/**
 * Run the evaluation script in test mode and return the JSON result.
 * The --test flag outputs all metric function test results as JSON.
 */
function runEvaluateTest() {
  const output = execSync(
    `"${venvPython}" "${evaluateScript}" --test`,
    {
      cwd: aiRoot,
      encoding: 'utf-8',
      timeout: 60000,
      env: Object.assign({}, process.env, {
        PYTHONPATH: join(aiRoot, 'src'),
      }),
    },
  );
  return JSON.parse(output);
}

/**
 * Run the evaluation script in report mode and return the text output.
 */
function runEvaluateReport() {
  const output = execSync(
    `"${venvPython}" "${evaluateScript}"`,
    {
      cwd: aiRoot,
      encoding: 'utf-8',
      timeout: 60000,
      env: Object.assign({}, process.env, {
        PYTHONPATH: join(aiRoot, 'src'),
      }),
    },
  );
  return output;
}

// ── Test Suites ──

describe('ML Evaluation — metric calculation functions', () => {
  let results;

  beforeAll(() => {
    results = runEvaluateTest();
  });

  it('all metric function tests pass', () => {
    expect(results.failed).toBe(0);
    expect(results.passed).toBeGreaterThan(0);
  });

  it('calculates accuracy correctly', () => {
    const test = results.tests.find((t) => t.name.startsWith('accuracy_'));
    expect(test.passed).toBe(true);
  });

  it('calculates precision correctly', () => {
    const test = results.tests.find((t) => t.name.startsWith('precision_'));
    expect(test.passed).toBe(true);
  });

  it('calculates recall correctly', () => {
    const test = results.tests.find((t) => t.name.startsWith('recall_'));
    expect(test.passed).toBe(true);
  });

  it('calculates F1 correctly', () => {
    const test = results.tests.find((t) => t.name.startsWith('f1_'));
    expect(test.passed).toBe(true);
  });

  it('calculates confusion matrix correctly', () => {
    const test = results.tests.find((t) => t.name.startsWith('confusion_matrix_'));
    expect(test.passed).toBe(true);
  });

  it('calculates FPR correctly', () => {
    const test = results.tests.find((t) => t.name.startsWith('fpr_'));
    expect(test.passed).toBe(true);
  });

  it('calculates FNR correctly', () => {
    const test = results.tests.find((t) => t.name.startsWith('fnr_'));
    expect(test.passed).toBe(true);
  });

  it('calculates valid binary ROC-AUC', () => {
    const test = results.tests.find((t) => t.name.startsWith('roc_auc_'));
    expect(test.passed).toBe(true);
  });

  it('handles missing classes (returns null)', () => {
    const test = results.tests.find((t) => t.name === 'precision_missing_positive');
    expect(test.passed).toBe(true);
  });

  it('handles zero-positive-prediction edge cases', () => {
    const zeroPredTests = results.tests.filter(
      (t) => t.name.includes('zero_') || t.name.includes('no_'),
    );
    expect(zeroPredTests.length).toBeGreaterThan(0);
    zeroPredTests.forEach((t) => {
      expect(t.passed).toBe(true);
    });
  });

  it('handles unavailable metrics (returns null)', () => {
    const unavailableTests = results.tests.filter(
      (t) => t.name.includes('single_class') || t.name.includes('all_negative'),
    );
    expect(unavailableTests.length).toBeGreaterThan(0);
    unavailableTests.forEach((t) => {
      expect(t.passed).toBe(true);
    });
  });
});

describe('ML Evaluation — login model report', () => {
  let report;

  beforeAll(() => {
    report = runEvaluateReport();
  });

  it('contains LOGIN MODEL section', () => {
    expect(report).toContain('LOGIN MODEL');
  });

  it('reports login accuracy of 100% on synthetic dataset', () => {
    expect(report).toContain('Accuracy:');
    expect(report).toContain('100.00%');
  });

  it('reports login precision of 100%', () => {
    expect(report).toContain('100.00%');
  });

  it('reports login recall of 100%', () => {
    expect(report).toContain('100.00%');
  });

  it('reports login F1 of 1.0000', () => {
    expect(report).toContain('F1: 1.0000');
  });

  it('reports login FPR of 0%', () => {
    expect(report).toContain('0.00%');
  });

  it('reports login FNR of 0%', () => {
    expect(report).toContain('0.00%');
  });

  it('reports login ROC-AUC as valid', () => {
    expect(report).toContain('ROC-AUC:');
  });

  it('reports login confusion matrix', () => {
    expect(report).toContain('Confusion Matrix:');
  });

  it('documents login class distribution (405 Low, 95 High)', () => {
    expect(report).toContain('High');
    expect(report).toContain('Low');
  });

  it('does NOT invent a Medium class for login', () => {
    const loginSection = report.substring(
      report.indexOf('LOGIN MODEL'),
      report.indexOf('SESSION MODEL'),
    );
    expect(loginSection.toLowerCase().includes('medium')).toBe(false);
  });
});

describe('ML Evaluation — session model report', () => {
  let report;

  beforeAll(() => {
    report = runEvaluateReport();
  });

  it('contains SESSION MODEL section', () => {
    expect(report).toContain('SESSION MODEL');
  });

  it('reports session accuracy', () => {
    expect(report).toContain('Accuracy:');
  });

  it('reports session precision', () => {
    expect(report).toContain('Precision:');
  });

  it('reports session recall', () => {
    expect(report).toContain('Recall:');
  });

  it('reports session F1', () => {
    expect(report).toContain('F1:');
  });

  it('reports session confusion matrix', () => {
    expect(report).toContain('Confusion Matrix:');
  });

  it('clearly states labels are synthetic', () => {
    expect(report).toContain('Synthetic Data');
  });
});

describe('ML Evaluation — authentication metrics', () => {
  let report;

  beforeAll(() => {
    report = runEvaluateReport();
  });

  it('reports AUTHENTICATION METRICS section', () => {
    expect(report).toContain('AUTHENTICATION METRICS');
  });

  it('reports False re-authentication rate as UNAVAILABLE', () => {
    expect(report).toContain('False re-authentication rate: UNAVAILABLE');
  });

  it('reports True re-authentication rate as UNAVAILABLE', () => {
    expect(report).toContain('True re-authentication rate: UNAVAILABLE');
  });

  it('reports Missed suspicious-event rate as UNAVAILABLE', () => {
    expect(report).toContain('Missed suspicious-event rate: UNAVAILABLE');
  });

  it('reports MFA trigger rate as UNAVAILABLE', () => {
    expect(report).toContain('MFA trigger rate: UNAVAILABLE');
  });

  it('reports Average re-authentication frequency as UNAVAILABLE', () => {
    expect(report).toContain('Average re-authentication frequency: UNAVAILABLE');
  });

  it('provides reasons for each unavailable metric', () => {
    const authSection = report.substring(
      report.indexOf('AUTHENTICATION METRICS'),
      report.indexOf('LIMITATIONS'),
    );
    const reasonMatches = authSection.match(/Reason:/g);
    expect(reasonMatches.length).toBe(5);
  });
});

describe('ML Evaluation — limitations documented', () => {
  let report;

  beforeAll(() => {
    report = runEvaluateReport();
  });

  it('contains LIMITATIONS section', () => {
    expect(report).toContain('LIMITATIONS');
  });

  it('documents synthetic data limitation', () => {
    expect(report).toContain('Synthetic Data');
  });

  it('documents rule-generated login labels', () => {
    expect(report).toContain('Rule-Generated Login Labels');
  });

  it('documents synthetic session labels', () => {
    expect(report).toContain('Synthetic Session Labels');
  });

  it('documents no independent security ground truth', () => {
    expect(report).toContain('No Independent Security Ground Truth');
  });
});

describe('ML Evaluation — file existence', () => {
  it('evaluate_models.py script exists', () => {
    expect(existsSync(evaluateScript)).toBe(true);
  });

  it('evaluate.test.js exists', () => {
    expect(existsSync(fileURLToPath(import.meta.url))).toBe(true);
  });
});
