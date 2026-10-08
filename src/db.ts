export interface Reading {
  id: string;
  patientId: string;
  deviceId: string;
  heartRate: number;
  rhythm: string;
  capturedAt: string;
}

// In-memory stand-in for the readings datastore.
const READINGS: Reading[] = [
  { id: "r1", patientId: "patient-1001", deviceId: "dev-aaa", heartRate: 72, rhythm: "normal", capturedAt: "2026-10-01T10:00:00Z" },
  { id: "r2", patientId: "patient-1002", deviceId: "dev-bbb", heartRate: 148, rhythm: "afib", capturedAt: "2026-10-02T11:30:00Z" },
];

export function readingsForPatient(patientId: string): Reading[] {
  return READINGS.filter((r) => r.patientId === patientId);
}
