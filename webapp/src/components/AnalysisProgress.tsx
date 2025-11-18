export interface AnalysisStep {
  id: string;
  label: string;
  status: 'pending' | 'in_progress' | 'completed' | 'error';
}

interface AnalysisProgressProps {
  steps: AnalysisStep[];
}

export function AnalysisProgress({ steps }: AnalysisProgressProps) {
  const completedSteps = steps.filter((s) => s.status === 'completed').length;
  const totalSteps = steps.length;
  const progressPercent = (completedSteps / totalSteps) * 100;

  return (
    <div className="space-y-4" role="progressbar" aria-valuenow={progressPercent} aria-valuemin={0} aria-valuemax={100}>
      {/* Progress Bar */}
      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 overflow-hidden">
        <div
          className="bg-blue-600 dark:bg-blue-500 h-full transition-all duration-500 ease-out"
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      {/* Steps List */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
        {steps.map((step) => (
          <div
            key={step.id}
            className={`flex items-center gap-2 text-sm ${
              step.status === 'completed'
                ? 'text-green-700 dark:text-green-400'
                : step.status === 'in_progress'
                ? 'text-blue-700 dark:text-blue-400'
                : step.status === 'error'
                ? 'text-red-700 dark:text-red-400'
                : 'text-gray-500 dark:text-gray-400'
            }`}
          >
            {step.status === 'completed' && <span className="text-lg">✓</span>}
            {step.status === 'in_progress' && (
              <span className="animate-spin inline-block">⟳</span>
            )}
            {step.status === 'error' && <span className="text-lg">✗</span>}
            {step.status === 'pending' && <span className="text-lg opacity-30">○</span>}
            <span className="font-medium">{step.label}</span>
          </div>
        ))}
      </div>

      {/* Status Text */}
      <p className="text-center text-sm text-gray-600 dark:text-gray-300">
        {completedSteps} of {totalSteps} checks completed ({Math.round(progressPercent)}%)
      </p>
    </div>
  );
}
