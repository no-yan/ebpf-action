//! TDD Refactoring Patterns for Systems Programming
//!
//! This file contains reusable patterns discovered during the bee-trace refactoring
//! from monolithic to loose coupling, high cohesion architecture.

use std::collections::HashMap;
use std::marker::PhantomData;

/// Pattern 1: Mock Interface for External Dependencies
/// 
/// Problem: External systems (eBPF, databases, networks) are hard to test
/// Solution: Abstract interface with mock implementation
/// 
/// Example: MockEbpf allows testing without kernel privileges
pub trait ExternalSystem<T> {
    type Error;
    
    fn connect(&mut self) -> Result<(), Self::Error>;
    fn execute(&mut self, operation: T) -> Result<(), Self::Error>;
    fn is_connected(&self) -> bool;
}

pub struct MockExternalSystem<T> {
    connected: bool,
    should_fail: bool,
    operations: Vec<T>,
}

impl<T> MockExternalSystem<T> {
    pub fn new() -> Self {
        Self {
            connected: false,
            should_fail: false,
            operations: Vec::new(),
        }
    }
    
    pub fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }
    
    pub fn operations(&self) -> &[T] {
        &self.operations
    }
}

impl<T: Clone> ExternalSystem<T> for MockExternalSystem<T> {
    type Error = String;
    
    fn connect(&mut self) -> Result<(), Self::Error> {
        if self.should_fail {
            return Err("Mock connection failure".to_string());
        }
        self.connected = true;
        Ok(())
    }
    
    fn execute(&mut self, operation: T) -> Result<(), Self::Error> {
        if !self.connected {
            return Err("Not connected".to_string());
        }
        if self.should_fail {
            return Err("Mock execution failure".to_string());
        }
        self.operations.push(operation);
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Pattern 2: Configuration Builder with Validation
/// 
/// Problem: Complex configuration from multiple sources needs validation
/// Solution: Builder pattern with separated validation step
/// 
/// Example: Unified configuration from CLI, files, environment
#[derive(Debug, Clone, PartialEq)]
pub struct ExampleConfig {
    pub name: String,
    pub timeout: u64,
    pub features: Vec<String>,
}

#[derive(Debug)]
pub struct ExampleConfigBuilder {
    name: Option<String>,
    timeout: Option<u64>,
    features: Vec<String>,
}

impl ExampleConfigBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            timeout: None,
            features: Vec::new(),
        }
    }
    
    pub fn from_cli_args(mut self, args: &[&str]) -> Result<Self, String> {
        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "--name" => {
                    if i + 1 < args.len() {
                        self.name = Some(args[i + 1].to_string());
                        i += 2;
                    } else {
                        return Err("Missing value for --name".to_string());
                    }
                }
                "--timeout" => {
                    if i + 1 < args.len() {
                        let timeout: u64 = args[i + 1].parse()
                            .map_err(|_| format!("Invalid timeout: {}", args[i + 1]))?;
                        self.timeout = Some(timeout);
                        i += 2;
                    } else {
                        return Err("Missing value for --timeout".to_string());
                    }
                }
                "--feature" => {
                    if i + 1 < args.len() {
                        self.features.push(args[i + 1].to_string());
                        i += 2;
                    } else {
                        return Err("Missing value for --feature".to_string());
                    }
                }
                _ => i += 1,
            }
        }
        Ok(self)
    }
    
    pub fn from_env(mut self) -> Result<Self, String> {
        if let Ok(name) = std::env::var("EXAMPLE_NAME") {
            self.name = Some(name);
        }
        if let Ok(timeout) = std::env::var("EXAMPLE_TIMEOUT") {
            self.timeout = Some(timeout.parse()
                .map_err(|_| format!("Invalid EXAMPLE_TIMEOUT: {}", timeout))?);
        }
        Ok(self)
    }
    
    pub fn build(self) -> Result<ExampleConfig, String> {
        let config = ExampleConfig {
            name: self.name.unwrap_or_else(|| "default".to_string()),
            timeout: self.timeout.unwrap_or(30),
            features: self.features,
        };
        
        // Validation separated from construction
        if config.name.is_empty() {
            return Err("Name cannot be empty".to_string());
        }
        if config.timeout == 0 {
            return Err("Timeout must be greater than 0".to_string());
        }
        
        Ok(config)
    }
}

/// Pattern 3: Manager Interface with State Tracking
/// 
/// Problem: Complex operations need lifecycle management and state tracking
/// Solution: Manager interface with clear state transitions
/// 
/// Example: ResourceManager abstracts complex resource lifecycle
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceType {
    FileHandle,
    NetworkConnection,
    MemoryRegion,
}

pub trait ResourceManager<R> {
    type Error;
    
    fn acquire(&mut self, resource_type: ResourceType) -> Result<(), Self::Error>;
    fn release(&mut self, resource_type: ResourceType) -> Result<(), Self::Error>;
    fn is_acquired(&self, resource_type: ResourceType) -> bool;
    fn acquired_resources(&self) -> Vec<ResourceType>;
}

pub struct ExampleResourceManager<R> {
    acquired: HashMap<ResourceType, bool>,
    _phantom: PhantomData<R>,
}

impl<R> ExampleResourceManager<R> {
    pub fn new() -> Self {
        Self {
            acquired: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

impl<R> ResourceManager<R> for ExampleResourceManager<R> {
    type Error = String;
    
    fn acquire(&mut self, resource_type: ResourceType) -> Result<(), Self::Error> {
        if self.acquired.get(&resource_type).copied().unwrap_or(false) {
            return Err(format!("Resource {:?} already acquired", resource_type));
        }
        
        // Simulate resource acquisition
        self.acquired.insert(resource_type, true);
        Ok(())
    }
    
    fn release(&mut self, resource_type: ResourceType) -> Result<(), Self::Error> {
        if !self.acquired.remove(&resource_type).unwrap_or(false) {
            return Err(format!("Resource {:?} not acquired", resource_type));
        }
        Ok(())
    }
    
    fn is_acquired(&self, resource_type: ResourceType) -> bool {
        self.acquired.get(&resource_type).copied().unwrap_or(false)
    }
    
    fn acquired_resources(&self) -> Vec<ResourceType> {
        self.acquired.keys().cloned().collect()
    }
}

/// Pattern 4: Application Coordination Layer
/// 
/// Problem: Need high-level coordination without tight coupling to specifics
/// Solution: Application layer that composes interfaces
/// 
/// Example: Application that coordinates configuration, resources, and external systems
pub struct ExampleApplication<R, S: ExternalSystem<String>> {
    config: ExampleConfig,
    resource_manager: Box<dyn ResourceManager<R, Error = String>>,
    external_system: S,
}

impl<R, S: ExternalSystem<String>> ExampleApplication<R, S> {
    pub fn new(
        config: ExampleConfig,
        resource_manager: Box<dyn ResourceManager<R, Error = String>>,
        external_system: S,
    ) -> Self {
        Self {
            config,
            resource_manager,
            external_system,
        }
    }
    
    pub fn initialize(&mut self) -> Result<(), String> {
        // Coordinate initialization across components
        self.external_system.connect()?;
        
        for feature in &self.config.features {
            match feature.as_str() {
                "file" => self.resource_manager.acquire(ResourceType::FileHandle)?,
                "network" => {
                    self.resource_manager.acquire(ResourceType::NetworkConnection)?;
                    self.external_system.execute("setup_network".to_string())?;
                }
                "memory" => self.resource_manager.acquire(ResourceType::MemoryRegion)?,
                _ => return Err(format!("Unknown feature: {}", feature)),
            }
        }
        
        Ok(())
    }
    
    pub fn is_ready(&self) -> bool {
        self.external_system.is_connected() && 
        !self.resource_manager.acquired_resources().is_empty()
    }
    
    pub fn status(&self) -> ApplicationStatus {
        ApplicationStatus {
            connected: self.external_system.is_connected(),
            acquired_resources: self.resource_manager.acquired_resources(),
            configured_features: self.config.features.clone(),
        }
    }
}

#[derive(Debug)]
pub struct ApplicationStatus {
    pub connected: bool,
    pub acquired_resources: Vec<ResourceType>,
    pub configured_features: Vec<String>,
}

/// Pattern 5: TDD Test Structure
/// 
/// Problem: Complex systems need comprehensive test coverage
/// Solution: Structured test approach with clear phases
/// 
/// Example: Test structure following Red-Green-Refactor methodology

#[cfg(test)]
mod tdd_pattern_examples {
    use super::*;

    // Red Phase: Define behavior through failing tests
    #[test]
    fn should_build_config_from_cli_args() {
        let config = ExampleConfigBuilder::new()
            .from_cli_args(&["--name", "test", "--timeout", "60", "--feature", "file"])
            .unwrap()
            .build()
            .unwrap();
        
        assert_eq!(config.name, "test");
        assert_eq!(config.timeout, 60);
        assert_eq!(config.features, vec!["file"]);
    }
    
    #[test]
    fn should_reject_invalid_timeout() {
        let result = ExampleConfigBuilder::new()
            .from_cli_args(&["--timeout", "invalid"]);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid timeout"));
    }
    
    // Green Phase: Test minimal implementation
    #[test]
    fn should_acquire_and_release_resources() {
        let mut manager = ExampleResourceManager::<()>::new();
        
        assert!(!manager.is_acquired(ResourceType::FileHandle));
        
        let result = manager.acquire(ResourceType::FileHandle);
        assert!(result.is_ok());
        assert!(manager.is_acquired(ResourceType::FileHandle));
        
        let result = manager.release(ResourceType::FileHandle);
        assert!(result.is_ok());
        assert!(!manager.is_acquired(ResourceType::FileHandle));
    }
    
    #[test]
    fn should_prevent_double_acquisition() {
        let mut manager = ExampleResourceManager::<()>::new();
        
        manager.acquire(ResourceType::FileHandle).unwrap();
        let result = manager.acquire(ResourceType::FileHandle);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already acquired"));
    }
    
    // Refactor Phase: Test integrated behavior
    #[test]
    fn should_initialize_application_with_features() {
        let config = ExampleConfigBuilder::new()
            .from_cli_args(&["--feature", "file", "--feature", "network"])
            .unwrap()
            .build()
            .unwrap();
        
        let resource_manager = Box::new(ExampleResourceManager::new());
        let external_system = MockExternalSystem::new();
        
        let mut app = ExampleApplication::new(config, resource_manager, external_system);
        
        let result = app.initialize();
        assert!(result.is_ok());
        assert!(app.is_ready());
        
        let status = app.status();
        assert!(status.connected);
        assert_eq!(status.configured_features, vec!["file", "network"]);
        assert!(status.acquired_resources.contains(&ResourceType::FileHandle));
        assert!(status.acquired_resources.contains(&ResourceType::NetworkConnection));
    }
    
    #[test]
    fn should_handle_initialization_failures() {
        let config = ExampleConfigBuilder::new()
            .from_cli_args(&["--feature", "network"])
            .unwrap()
            .build()
            .unwrap();
        
        let resource_manager = Box::new(ExampleResourceManager::new());
        let external_system = MockExternalSystem::new().with_failure();
        
        let mut app = ExampleApplication::new(config, resource_manager, external_system);
        
        let result = app.initialize();
        assert!(result.is_err());
        assert!(!app.is_ready());
    }
}

/// Pattern 6: Error Handling with Context
/// 
/// Problem: Systems programming errors need detailed context for debugging
/// Solution: Structured error types with error chaining
/// 
/// Example: Comprehensive error handling for complex operations

#[derive(Debug)]
pub enum ExampleError {
    ConfigError { message: String },
    ResourceError { resource_type: ResourceType, source: String },
    ExternalSystemError { operation: String, source: String },
    ValidationError { field: String, value: String, expected: String },
}

impl std::fmt::Display for ExampleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExampleError::ConfigError { message } => {
                write!(f, "Configuration error: {}", message)
            }
            ExampleError::ResourceError { resource_type, source } => {
                write!(f, "Resource error for {:?}: {}", resource_type, source)
            }
            ExampleError::ExternalSystemError { operation, source } => {
                write!(f, "External system error during {}: {}", operation, source)
            }
            ExampleError::ValidationError { field, value, expected } => {
                write!(f, "Validation error: field '{}' has value '{}', expected {}", 
                       field, value, expected)
            }
        }
    }
}

impl std::error::Error for ExampleError {}

/// Pattern Summary:
/// 
/// These patterns enable:
/// 1. **Testability**: Mock interfaces allow testing without external dependencies
/// 2. **Flexibility**: Configuration builder supports multiple sources
/// 3. **Maintainability**: Clear interfaces and state management
/// 4. **Reliability**: Comprehensive error handling with context
/// 5. **Composability**: Application layer coordinates without tight coupling
/// 
/// Key TDD Insights:
/// - Start with behavior definition (Red phase)
/// - Implement minimally to pass tests (Green phase)  
/// - Refactor for production needs while maintaining tests
/// - Use mock interfaces for external dependencies
/// - Separate configuration, validation, and business logic
/// - Structure errors with detailed context for debugging
/// 
/// These patterns are applicable to any systems programming project requiring:
/// - High testability with external dependencies
/// - Complex configuration management
/// - Clear separation of concerns
/// - Reliable error handling and debugging