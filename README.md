👉 Main library: [nopii](https://github.com/ay-mich/nopii)

# NoPII Examples

A collection of practical examples demonstrating how to use the NoPII library for PII detection, transformation, and data privacy protection.

## 🚀 Quick Start

1. **Install NoPII**: `pip install nopii`
2. **Run any example**: `python examples/01_getting_started.py`
3. **Check outputs**: Generated files will be in the `examples/outputs/` directory

## 📁 Repository Structure

```
nopii-examples/
├── examples/                          # Example scripts
│   ├── 01_getting_started.py         # Basic PII detection and transformation
│   ├── 02_detectors_and_transformers.py  # Exploring different detectors and transformers
│   ├── 03_advanced_policies.py       # Custom policies and advanced configurations
│   ├── 04_reporting_and_analysis.py  # Comprehensive reporting and analysis
│   ├── 05_real_world_examples.py     # Production-ready patterns and best practices
│   ├── 06_compliance_and_governance.py  # Regulatory compliance (GDPR, HIPAA, CCPA)
│   └── outputs/                      # Generated outputs (created when scripts run)
│       ├── compliance_outputs/       # Compliance reports and governance artifacts
│       ├── data/                     # Transformed datasets and sample data
│       ├── policies/                 # Generated policy files
│       ├── reports/                  # HTML, JSON, and Markdown reports
│       └── sample_data/              # Sample datasets for testing
```

## 📚 Examples Overview

### 1. Getting Started (`01_getting_started.py`)

- Basic PII detection in DataFrames
- Simple transformations (redaction, masking)
- Understanding confidence scores
- Working with different data types

### 2. Detectors and Transformers (`02_detectors_and_transformers.py`)

- Exploring built-in PII detectors
- Comparing transformation methods
- Custom detector configurations
- Performance considerations

### 3. Advanced Policies (`03_advanced_policies.py`)

- Creating custom detection policies
- Policy inheritance and composition
- Environment-specific configurations
- Policy validation and testing

### 4. Reporting and Analysis (`04_reporting_and_analysis.py`)

- Comprehensive PII analysis reports
- Risk assessment and scoring
- Data quality metrics
- Export formats (HTML, JSON, Markdown)

### 5. Real-World Examples (`05_real_world_examples.py`)

- Production-ready patterns
- Data pipeline integration
- Configuration management
- Performance optimization
- Best practices and checklists

### 6. Compliance and Governance (`06_compliance_and_governance.py`)

- Regulatory compliance frameworks (GDPR, HIPAA, CCPA)
- Automated compliance policy creation
- Audit trail generation and reporting
- Data governance dashboard metrics
- Breach notification and consumer request workflows

## 🔧 Requirements

- Python 3.8+
- NoPII library (`pip install nopii`)
- pandas, sqlite3 (usually included with Python)

## 🎯 Key Features Demonstrated

- **PII Detection**: Email, phone, SSN, credit cards, names, addresses
- **Transformations**: Redaction, masking, hashing, tokenization
- **Policies**: Custom rules, confidence thresholds, data type handling
- **Reporting**: Detailed analysis, risk assessment, compliance metrics
- **Integration**: Database connections, file processing, pipeline patterns

## 📊 Output Files

All generated files are organized in the `examples/outputs/` directory:

- **Reports**: Detailed analysis in HTML, JSON, and Markdown formats
- **Data**: Transformed datasets and sample files for testing
- **Policies**: Custom policy configurations in YAML/JSON
- **Performance**: Benchmarking and optimization results

## 🛡️ Privacy & Security

These examples demonstrate privacy-preserving techniques:

- ✅ PII detection and classification
- ✅ Secure data transformation
- ✅ Risk assessment and scoring
- ✅ Compliance reporting
- ✅ Data minimization strategies

## 🤝 Contributing

Feel free to contribute additional examples or improvements:

1. Fork the repository
2. Create a feature branch
3. Add your example with clear documentation
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

- [NoPII Documentation](https://ay-mich.github.io/nopii/nopii.html)
- [NoPII GitHub Repository](https://github.com/ay-mich/nopii)
