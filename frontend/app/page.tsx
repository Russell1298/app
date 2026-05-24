import DomainForm from '@/components/DomainForm'

export default function Home() {
  return (
    <div>
      <div className="text-center mb-12 pt-6">
        <h1 className="text-3xl font-bold text-white mb-3">
          Website Security Assessment
        </h1>
        <p className="text-gray-400 max-w-xl mx-auto">
          Scan any domain for publicly visible security weaknesses — missing headers,
          exposed files, weak TLS, and email spoofing risks. Passive only, no exploitation.
        </p>
      </div>
      <DomainForm />
    </div>
  )
}
